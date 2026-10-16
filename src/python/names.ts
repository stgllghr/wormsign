/**
 * Python project names: PEP 508's name rule, PEP 503 normalisation, and the one validated form wormsign puts in a
 * URL or sends to OSV.
 *
 * - PEP 508 (https://peps.python.org/pep-0508/#names): `^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$`, case-insensitive.
 * - PEP 503 (https://peps.python.org/pep-0503/#normalized-names): `re.sub(r"[-_.]+", "-", name).lower()`.
 * - The normalised form wormsign accepts is exactly what src/osv.ts sends to OSV for PyPI (OSV_VALID.PyPI.name): at most
 *   200 characters, lowercase, PEP 508-shaped and already normalised. test/python-readers.test.ts checks that the two
 *   accept the same set.
 */

const PEP508_NAME = /^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$/i;
const NORMALIZED = /^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/;

/** PyPI's limit on project name length is not in a PEP; 200 is the bound src/osv.ts uses. */
export const MAX_NAME_LENGTH = 200;

/** PEP 503 normalisation. Does not validate. */
export function normalizeName(name: string): string {
  return name.replace(/[-_.]+/g, "-").toLowerCase();
}

/** A name PEP 508 allows (any case, any of "-", "_", "."). */
export function isValidName(name: string): boolean {
  return PEP508_NAME.test(name);
}

/** A name that is already in the one form wormsign uses: normalised, valid and at most 200 characters. */
export function isNormalizedName(name: string): boolean {
  return name.length <= MAX_NAME_LENGTH && NORMALIZED.test(name) && name === normalizeName(name);
}

/** The normalised form of a valid name, or undefined when the name is not valid or too long once normalised. */
export function projectName(raw: string): string | undefined {
  if (!isValidName(raw)) return undefined;
  const n = normalizeName(raw);
  return isNormalizedName(n) ? n : undefined;
}
