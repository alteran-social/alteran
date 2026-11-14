export type SemanticCheck = "valid" | "invalid" | "unsupported";
export type SemanticBudget = {
  remainingGraphemeUnits: number;
  segmenter?: Intl.Segmenter;
};

const encoder = new TextEncoder();

function numberField(definition: Record<string, unknown>, name: string) {
  const value = definition[name];
  return typeof value === "number" ? value : undefined;
}

function orderedBounds(
  definition: Record<string, unknown>,
  minimumName: string,
  maximumName: string,
  nonnegative: boolean,
): boolean {
  const minimum = numberField(definition, minimumName);
  const maximum = numberField(definition, maximumName);
  return !(
    (nonnegative && minimum !== undefined && minimum < 0) ||
    (nonnegative && maximum !== undefined && maximum < 0) ||
    (minimum !== undefined && maximum !== undefined && minimum > maximum)
  );
}

function insideBounds(value: number, minimum?: number, maximum?: number) {
  return (minimum === undefined || value >= minimum) &&
    (maximum === undefined || value <= maximum);
}

function stringInsideBounds(
  value: string,
  definition: Record<string, unknown>,
  budget: SemanticBudget,
): SemanticCheck {
  const length = encoder.encode(value).byteLength;
  if (
    !insideBounds(
      length,
      numberField(definition, "minLength"),
      numberField(definition, "maxLength"),
    )
  ) return "invalid";

  const minimum = numberField(definition, "minGraphemes");
  const maximum = numberField(definition, "maxGraphemes");
  if (minimum !== undefined || maximum !== undefined) {
    if (typeof Intl.Segmenter !== "function") return "unsupported";
    budget.remainingGraphemeUnits -= Math.max(value.length, 16);
    if (budget.remainingGraphemeUnits < 0) return "unsupported";
    budget.segmenter ??= new Intl.Segmenter("und", { granularity: "grapheme" });
    let graphemes = 0;
    for (const _segment of budget.segmenter.segment(value)) {
      graphemes++;
      if (maximum !== undefined && graphemes > maximum) return "invalid";
    }
    if (!insideBounds(graphemes, minimum, maximum)) return "invalid";
  }
  // Syntax formats can change with the protocol; no validator is selected here.
  return definition.format === undefined ? "valid" : "unsupported";
}

function validMimeRange(value: string): boolean {
  if (value === "*/*") return true;
  return /^[A-Za-z0-9!#$%&'+.^_`|~-]+\/(?:\*|[A-Za-z0-9!#$%&'+.^_`|~-]+)$/.test(
    value,
  );
}

/** Check bounds and literal consistency after SDK structural validation. */
export function checkLexiconValueConstraints(
  definition: Record<string, unknown>,
  budget: SemanticBudget,
): SemanticCheck {
  const type = definition.type;
  if (type === "boolean" || type === "integer" || type === "string") {
    const hasDefault = definition.default !== undefined;
    const hasConstant = definition.const !== undefined;
    if (
      hasDefault && hasConstant &&
      (type === "string" || definition.default !== definition.const)
    ) return "invalid";

    if (
      type === "integer" && !orderedBounds(
        definition,
        "minimum",
        "maximum",
        false,
      )
    ) return "invalid";
    if (
      type === "string" && (!orderedBounds(
        definition,
        "minLength",
        "maxLength",
        true,
      ) || !orderedBounds(definition, "minGraphemes", "maxGraphemes", true))
    ) {
      return "invalid";
    }

    const allowed = Array.isArray(definition.enum)
      ? definition.enum
      : undefined;
    if (allowed) {
      if (hasConstant && !allowed.includes(definition.const)) return "invalid";
      if (hasDefault && !allowed.includes(definition.default)) return "invalid";
      if (allowed.length === 0) return "unsupported";
    }
    const values = [
      ...(hasDefault ? [definition.default] : []),
      ...(hasConstant ? [definition.const] : []),
      ...(allowed ?? []),
    ];
    let unsupported = false;
    for (const value of values) {
      if (type === "integer") {
        if (
          typeof value !== "number" || !insideBounds(
            value,
            numberField(definition, "minimum"),
            numberField(definition, "maximum"),
          )
        ) return "invalid";
      } else if (type === "string") {
        if (typeof value !== "string") return "invalid";
        const result = stringInsideBounds(value, definition, budget);
        if (result === "invalid") return result;
        if (result === "unsupported") unsupported = true;
      }
    }
    return unsupported ? "unsupported" : "valid";
  }
  if (type === "bytes" || type === "array") {
    return orderedBounds(definition, "minLength", "maxLength", true)
      ? "valid"
      : "invalid";
  }
  if (type === "blob") {
    const maxSize = numberField(definition, "maxSize");
    if (maxSize !== undefined && maxSize < 0) return "invalid";
    if (
      Array.isArray(definition.accept) &&
      !definition.accept.every((item) =>
        typeof item === "string" && validMimeRange(item)
      )
    ) return "invalid";
  }
  return "valid";
}
