import { lexiconDocumentSchema } from "@atproto/lex-document";
import { isValidNsid } from "@atproto/syntax-spaces";
import { copyLexicon } from "./lexicon-semantics-copy";
import { checkLexiconDataModel } from "./lexicon-semantics-data";
import {
  checkLexiconValueConstraints,
  type SemanticCheck,
} from "./lexicon-semantics-values";

export type SpaceLexiconSemantics =
  | { readonly tag: "valid" }
  | { readonly tag: "invalid" }
  | { readonly tag: "unsupported" };

type Position = "main" | "named" | "property" | "item";
type SchemaNode = { readonly value: unknown; readonly position: Position };

const concrete = ["boolean", "integer", "string", "bytes", "cid-link", "blob"];
const named = new Set([...concrete, "array", "object", "token"]);
const property = new Set([...concrete, "array", "ref", "union", "unknown"]);
const item = new Set([...concrete, "ref", "union", "unknown"]);
const known = new Set([
  ...named,
  ...property,
  "space",
  "record",
  "query",
  "procedure",
  "subscription",
  "params",
  "permission-set",
  "permission",
]);
const formats = new Set([
  "at-identifier",
  "at-uri",
  "cid",
  "datetime",
  "did",
  "handle",
  "language",
  "nsid",
  "record-key",
  "space-ref",
  "tid",
  "uri",
]);

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function referenceCheck(
  reference: string,
  kind: "ref" | "union",
  id: string,
  definitions: Record<string, unknown>,
): SemanticCheck {
  const parts = reference.split("#");
  if (parts.length > 2 || !reference || (parts.length === 2 && !parts[1])) {
    return "invalid";
  }
  const authority = parts[0];
  if (!authority && parts.length !== 2) return "invalid";
  if (authority && !isValidNsid(authority)) return "invalid";
  if (authority && authority !== id) return "unsupported";
  const name = parts.length === 2 ? parts[1] : "main";
  if (!Object.hasOwn(definitions, name)) return "invalid";
  const target = definitions[name];
  if (!isObject(target) || typeof target.type !== "string") return "invalid";
  if (kind === "union") return target.type === "object" ? "valid" : "invalid";
  return named.has(target.type) && target.type !== "token"
    ? "valid"
    : "invalid";
}

function scanSchemaPositions(
  definitions: Record<string, unknown>,
): SemanticCheck {
  const pending: SchemaNode[] = Object.entries(definitions).map((
    [name, value],
  ) => ({
    value,
    position: name === "main" ? "main" : "named",
  }));
  while (pending.length) {
    const next = pending.pop();
    if (!next || !isObject(next.value) || typeof next.value.type !== "string") {
      return "invalid";
    }
    const definition = next.value;
    const type = definition.type as string;
    if (!known.has(type)) return "unsupported";
    const allowed = next.position === "main"
      ? type === "space"
      : next.position === "named"
      ? named.has(type)
      : next.position === "property"
      ? property.has(type)
      : item.has(type);
    if (!allowed) return "invalid";
    if (type === "string" && definition.format !== undefined) {
      if (typeof definition.format !== "string") return "invalid";
      if (!formats.has(definition.format)) return "unsupported";
    }
    if (type === "object") {
      if (!isObject(definition.properties)) return "invalid";
      for (const value of Object.values(definition.properties)) {
        pending.push({ value, position: "property" });
      }
    } else if (type === "array") {
      pending.push({ value: definition.items, position: "item" });
    }
  }
  return "valid";
}

/**
 * Check the pinned alpha Space-Lexicon subset without resolving references.
 * A valid result is not proof of publication, freshness, identity, or consent.
 * Only the supported JSON-like data-model subset within local budgets is handled.
 * Bytes, links, blobs, unknown reserved fields, external references, formatted
 * literals and future syntax return unsupported. A standalone document may omit
 * $type; a published record and its exact bytes must be authenticated separately.
 * Local references are checked without expansion, so recursive definitions are
 * supported. Ordinary extension fields are ignored.
 */
export function validateSpaceLexiconSemantics(
  input: unknown,
): SpaceLexiconSemantics {
  const copied = copyLexicon(input);
  if (copied.tag !== "copied") return { tag: copied.tag };
  const document = copied.value;
  if (!isObject(document)) return { tag: "invalid" };
  if (
    Object.hasOwn(document, "$type") &&
    document.$type !== "com.atproto.lexicon.schema"
  ) return { tag: "invalid" };
  const dataModel = checkLexiconDataModel(document);
  if (dataModel !== "valid") return { tag: dataModel };
  if (document.lexicon !== 1) {
    return {
      tag: Number.isSafeInteger(document.lexicon) ? "unsupported" : "invalid",
    };
  }
  if (
    typeof document.id !== "string" || !isValidNsid(document.id) ||
    !isObject(document.defs) || !Object.hasOwn(document.defs, "main")
  ) return { tag: "invalid" };
  const id = document.id;
  const definitions = document.defs;
  if (Object.keys(definitions).some((name) => !name)) return { tag: "invalid" };
  if (Object.keys(definitions).some((name) => name.includes("#"))) {
    return { tag: "unsupported" };
  }
  const positions = scanSchemaPositions(definitions);
  if (positions !== "valid") return { tag: positions };
  try {
    if (!lexiconDocumentSchema.safeParse(document).success) {
      return { tag: "invalid" };
    }
  } catch {
    return { tag: "invalid" };
  }

  let unsupported = false;
  const budget = { remainingGraphemeUnits: 32_768 };
  const pending: Record<string, unknown>[] = Object.values(definitions).filter(
    isObject,
  );
  while (pending.length) {
    const definition = pending.pop();
    if (!definition) break;
    const result = checkLexiconValueConstraints(definition, budget);
    if (result === "invalid") return { tag: "invalid" };
    if (result === "unsupported") unsupported = true;

    if (definition.type === "object") {
      if (!isObject(definition.properties)) return { tag: "invalid" };
      const properties = definition.properties;
      for (const field of ["required", "nullable"]) {
        const names = definition[field];
        if (
          Array.isArray(names) &&
          names.some((name) =>
            typeof name !== "string" || !Object.hasOwn(properties, name)
          )
        ) return { tag: "invalid" };
      }
      for (const property of Object.values(properties)) {
        if (isObject(property)) pending.push(property);
      }
    } else if (definition.type === "array") {
      if (isObject(definition.items)) pending.push(definition.items);
    } else if (definition.type === "ref" || definition.type === "union") {
      const references = definition.type === "ref"
        ? [definition.ref]
        : definition.refs;
      if (!Array.isArray(references)) return { tag: "invalid" };
      if (
        definition.type === "union" && definition.closed === true &&
        !references.length
      ) {
        return { tag: "invalid" };
      }
      for (const reference of references) {
        if (typeof reference !== "string") return { tag: "invalid" };
        const result = referenceCheck(
          reference,
          definition.type,
          id,
          definitions,
        );
        if (result === "invalid") return { tag: "invalid" };
        if (result === "unsupported") unsupported = true;
      }
    }
  }
  return { tag: unsupported ? "unsupported" : "valid" };
}
