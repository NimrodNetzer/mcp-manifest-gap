// Static (never executed) extraction of MCP tool declarations from a package's JS.
// Usage: node extract_tools.js <package_dir>  -> JSON on stdout
const fs = require("fs"), path = require("path");
const acorn = require(process.env.ACORN || "acorn"), walk = require(process.env.ACORN_WALK || "acorn-walk");

function files(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { if (e.name !== "node_modules" && !["test","tests","__tests__","fixtures","examples","example"].includes(e.name)) files(p, out); }
    else if (/\.(m|c)?js$/.test(e.name) && !/\.(test|spec)\.(m|c)?js$/.test(e.name) && !/\.min\.js$/.test(e.name) && fs.statSync(p).size < 3e6) out.push(p);
  }
  return out;
}
function str(n) {
  if (!n) return null;
  if (n.type === "Literal" && typeof n.value === "string") return n.value;
  if (n.type === "TemplateLiteral") return n.quasis.map(q => q.value.cooked ?? "").join("${…}");
  if (n.type === "BinaryExpression" && n.operator === "+") { const a = str(n.left), b = str(n.right); if (a !== null || b !== null) return (a ?? "…") + (b ?? "…"); }
  if (n.type === "CallExpression" && n.callee.type === "MemberExpression" && n.callee.property.name === "join" && n.callee.object.type === "ArrayExpression")
    return n.callee.object.elements.map(e => str(e) ?? "…").join(str(n.arguments[0]) ?? ",");
  return null;
}
function prop(obj, ...names) {
  if (!obj || obj.type !== "ObjectExpression") return null;
  for (const p of obj.properties) if (p.type === "Property" && !p.computed) {
    const k = p.key.name ?? p.key.value; if (names.includes(k)) return p.value;
  }
  return null;
}
function schemaTexts(node) {  // every description / .describe() string inside a schema
  const out = [];
  if (!node) return out;
  walk.full(node, n => {
    if (n.type === "Property" && !n.computed && (n.key.name ?? n.key.value) === "description") { const s = str(n.value); if (s) out.push(s); }
    if (n.type === "CallExpression" && n.callee.type === "MemberExpression" && n.callee.property.name === "describe") { const s = str(n.arguments[0]); if (s) out.push(s); }
  });
  return out;
}
function paramNames(node) {
  const props = prop(node, "properties") || node; const out = [];
  if (props && props.type === "ObjectExpression") for (const p of props.properties) if (p.type === "Property") { const k = p.key.name ?? p.key.value; if (typeof k === "string") out.push(k); }
  return out;
}
const tools = [], seen = new Set();
function add(t, file) {
  if (!t.name || t.description == null) return;
  const k = t.name + "\u0000" + t.description; if (seen.has(k)) return; seen.add(k);
  tools.push({ ...t, file });
}
const dir = process.argv[2];
let parsed = 0, failed = 0;
for (const f of files(dir)) {
  const src = fs.readFileSync(f, "utf8"); let ast;
  for (const sourceType of ["module", "script"]) {
    try { ast = acorn.parse(src, { ecmaVersion: "latest", sourceType, allowHashBang: true, allowReturnOutsideFunction: true }); break; } catch { }
  }
  if (!ast) { failed++; continue; } parsed++;
  const rel = path.relative(dir, f);
  walk.full(ast, n => {
    if (n.type === "CallExpression" && n.callee.type === "MemberExpression" && ["tool", "registerTool"].includes(n.callee.property.name)) {
      const a = n.arguments, name = str(a[0]);
      if (!name) return;
      if (n.callee.property.name === "registerTool" && a[1]?.type === "ObjectExpression") {
        const sch = prop(a[1], "inputSchema");
        add({ name, description: str(prop(a[1], "description")) ?? "", title: str(prop(a[1], "title")), params: paramNames(sch), param_texts: schemaTexts(sch), via: "registerTool" }, rel);
      } else if (n.callee.property.name === "tool") {
        const desc = str(a[1]); const sch = desc !== null ? a[2] : a[1];
        if (a.length >= 2) add({ name, description: desc ?? "", params: sch?.type === "ObjectExpression" ? paramNames(sch) : [], param_texts: schemaTexts(sch?.type === "ObjectExpression" ? sch : null), via: "tool()" }, rel);
      }
    }
    if (n.type === "ObjectExpression") {
      const name = str(prop(n, "name")), desc = prop(n, "description"), sch = prop(n, "inputSchema", "input_schema");
      if (name && desc && sch) add({ name, description: str(desc) ?? "", params: paramNames(sch), param_texts: schemaTexts(sch), via: "object" }, rel);
    }
  });
}
process.stdout.write(JSON.stringify({ parsed, failed, tools }));
