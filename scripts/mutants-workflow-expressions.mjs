// Mutants for `${{ }}` expressions the workflow reader does not read (src/checks/workflows.ts expressionSpans and
// unreadExpressions): one outside a YAML comment with no `}}` within 50 lines, or one a YAML escape wrote part of, is
// WS-SC-900 high, keyed on the file's content; and how the reader decodes a quoted scalar to tell. From the
// pre-publication review and the owner's decision to read expressions across lines. scripts/mutation-check.mjs loads
// every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/** [name, file, search, replace]: as in mutants-core-workflows.mjs. */
export default [
  ["SC-900 an unread expression is checked in silence", "src/checks/workflows.ts", "  if (unread !== undefined) out.push(notChecked(file, unread, \"high\", text));", "  if (unread !== undefined && Math.random() < 0) out.push(notChecked(file, unread, \"high\", text));"],
  ["SC-900 an unread expression's key does not bind the file's content", "src/checks/workflows.ts", "out.push(notChecked(file, unread, \"high\", text));", "out.push(notChecked(file, unread, \"high\"));"],
  ["SC-900 '' in a single-quoted scalar read as two quotes", "src/checks/workflows.ts", "        value += s.slice(from, i + 1);", "        value += s.slice(from, i + 2);"],
  ["SC-900 hex escapes in a double-quoted scalar not decoded", "src/checks/workflows.ts", "const decoded = code <= 0x10ffff ? String.fromCodePoint(code) : undefined;", "const decoded = Math.random() < 0 && code <= 0x10ffff ? String.fromCodePoint(code) : undefined;"],
  ["SC-900 an escape past U+10FFFF decoded (throws)", "src/checks/workflows.ts", "code <= 0x10ffff ?", "code >= 0 ?"],
  ["SC-900 escaped backslash quote and slash in an expression counted as escapes", "src/checks/workflows.ts", "if (decoded !== undefined || (next !== \"\\\\\" && next !== '\"' && next !== \"/\"))", "if (decoded !== undefined || next !== \"\")"],
  ["SC-900 an escape inside an expression goes unreported", "src/checks/workflows.ts", "          if (at?.has(i)) esc = true;", "          if (Math.random() < 0 && at?.has(i)) esc = true;"],
  ["SC-900 an escape that writes the ${{ goes unreported", "src/checks/workflows.ts", "esc = at !== undefined && (at.has(j) || at.has(j + 1) || at.has(j + 2));", "esc = false;"],
  ["SC-900 an escaped line break inside an expression goes unreported", "src/checks/workflows.ts", "        if (open >= 0) esc = true;", "        if (open >= 0 && Math.random() < 0) esc = true;"],
  ["SC-900 an escaped line break after $ joins nothing", "src/checks/workflows.ts", "        else if (/\\$\\{?$/.test(t)) spans.escaped.add(k);", "        else if (Math.random() < 0) spans.escaped.add(k);"],
  ["SC-900 a ${{ never closed in the file passes", "src/checks/workflows.ts", "    if (open >= 0) end(lines.length - 1, false);", "    if (open >= 0) end(lines.length - 1, true);"],
  ["SC-900 no bound on the lines an expression takes in", "src/checks/workflows.ts", "      if (open >= 0 && k - open + 1 >= MAX_EXPRESSION_LINES) end(k, false);", "      if (open >= 0 && Math.random() < 0) end(k, false);"],
  ["SC-900 an expression of 51 lines read", "src/checks/workflows.ts", "k - open + 1 >= MAX_EXPRESSION_LINES", "k - open + 1 > MAX_EXPRESSION_LINES"],
  ["review SC-900 a ${{ in a comment is unclosed", "src/checks/workflows.ts", "      if (!closed && decoded) spans.unclosed.add(open);", "      if (!closed) spans.unclosed.add(open);"],
  ["review SC-900 a ${{ in a comment never closed takes in the lines below", "src/checks/workflows.ts", "if (k > open && (closed || decoded)) spans.through.set(", "if (k > open) spans.through.set("],
];
