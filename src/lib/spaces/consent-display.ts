import {
  copyIssuedSpacePermission,
  type SpaceRecordAction,
} from "./oauth-scopes";

export type SpaceConsentDescription = {
  readonly target: string;
  readonly permissions: readonly string[];
  readonly broad: boolean;
};

/** Describe an already-authenticated issued grant as plain text for consent. */
export function describeSpaceConsent(
  input: unknown,
): SpaceConsentDescription | null {
  const value = copyIssuedSpacePermission(input);
  if (!value) return null;
  const type = value.spaceType === "*"
    ? "all space types"
    : `space type ${value.spaceType}`;
  const authority = value.authority === "*"
    ? "any authority"
    : `authority ${value.authority}`;
  const key = value.skey === "*" ? "any space key" : `space key ${value.skey}`;
  const permissions: string[] = [];
  if (value.actions.includes("read") || value.actions.includes("read_self")) {
    permissions.push("Read your own repository in matching spaces");
    permissions.push(
      "Read settings, policies, member lists, writer identities and sync state for matching spaces you govern",
    );
  }
  if (value.actions.includes("read")) {
    permissions.push(
      "Request credentials to read other repositories in matching spaces",
    );
  }
  const writeActions: readonly SpaceRecordAction[] = [
    "create",
    "update",
    "delete",
  ];
  const actions = writeActions.filter((action) =>
    value.actions.includes(action)
  );
  if (actions.length && value.collections.values.length) {
    const collections = value.collections.values.includes("*")
      ? "any collection"
      : joinWords(value.collections.values);
    permissions.push(
      `${
        capitalize(joinWords(actions))
      } records in ${collections} in your own repository`,
    );
  }
  if (
    actions.length && value.collectionSource === "declaration" &&
    value.spaceType !== "*"
  ) {
    permissions.push(
      "Future authorization may include additional collections declared for this space type",
    );
  }
  if (value.manage.includes("create")) {
    permissions.push(
      "Create matching spaces that you govern and perform policy-specific creation operations",
    );
  }
  if (value.manage.includes("update")) {
    permissions.push(
      "Change settings and policies, manage members, remove writers and perform policy-specific updates in matching spaces you govern",
    );
  }
  if (value.manage.includes("delete")) {
    permissions.push(
      "Delete matching spaces that you govern and perform policy-specific deletion operations",
    );
  }
  return {
    target: `${type}, ${authority}, ${key}`,
    permissions,
    broad: value.spaceType === "*" || value.authority === "*" ||
      value.skey === "*" ||
      (actions.length > 0 &&
        (value.collections.values.includes("*") ||
          (value.collectionSource === "declaration" &&
            value.spaceType !== "*"))),
  };
}

function joinWords(words: readonly string[]): string {
  if (words.length <= 1) return words[0] ?? "";
  return `${words.slice(0, -1).join(", ")} and ${words[words.length - 1]}`;
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
