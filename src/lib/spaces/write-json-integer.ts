const MIN_INTEGER = -(1n << 63n);
const MAX_INTEGER = (1n << 63n) - 1n;
const MIN_SAFE = BigInt(Number.MIN_SAFE_INTEGER);
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

export const MAX_NUMBER_TOKEN_LENGTH = 128;
export const MAX_EXPONENT_MAGNITUDE = 128;

/** Convert an exact JSON number token to a signed-64-bit integer. */
export function parseExactSpaceInteger(source: unknown): number | bigint {
  if (
    typeof source !== "string" || source.length < 1 ||
    source.length > MAX_NUMBER_TOKEN_LENGTH
  ) throw invalid();
  const parts = /^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?)([0-9]+))?$/
    .exec(source);
  if (!parts) throw invalid();
  const fraction = parts[3] ?? "";
  const exponentDigits = (parts[5] ?? "0").replace(/^0+/, "") || "0";
  if (exponentDigits.length > 3) throw invalid();
  const magnitude = Number(exponentDigits);
  if (!Number.isSafeInteger(magnitude) || magnitude > MAX_EXPONENT_MAGNITUDE) {
    throw invalid();
  }
  const exponent = parts[4] === "-" ? -magnitude : magnitude;
  let digits = (parts[2] + fraction).replace(/^0+/, "");
  if (!digits) return 0;
  const scale = exponent - fraction.length;
  if (scale < 0) {
    const trailing = -scale;
    if (trailing >= digits.length || !/^0+$/.test(digits.slice(-trailing))) {
      throw invalid();
    }
    digits = digits.slice(0, -trailing);
  } else {
    if (digits.length + scale > 19) throw invalid();
    digits += "0".repeat(scale);
  }
  if (digits.length > 19) throw invalid();
  const integer = BigInt((parts[1] === "-" ? "-" : "") + digits);
  if (integer < MIN_INTEGER || integer > MAX_INTEGER) throw invalid();
  return integer >= MIN_SAFE && integer <= MAX_SAFE ? Number(integer) : integer;
}

function invalid(): Error {
  return new Error("Invalid Space write JSON");
}
