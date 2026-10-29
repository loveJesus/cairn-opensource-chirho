// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The cairn Tailwind-lite: a small, npm-free utility + component CSS so every app looks clean and
//! professional by default. Theme by overriding the `--brand-chirho` custom property (this is how a
//! product like perffection applies its own skin without forking the stylesheet).

/// The full utility + component stylesheet, inlined by the page shell (small; one source of truth).
pub const UI_CSS_CHIRHO: &str = r#":root{
  --brand-chirho:#4f46e5;--brand-ink-chirho:#fff;--brand-weak-chirho:rgba(79,70,229,.12);
  --bg-chirho:#f6f7f9;--surface-chirho:#fff;--ink-chirho:#18181b;--muted-chirho:#6b7280;
  --border-chirho:#e5e7eb;--radius-chirho:10px;
  --shadow-chirho:0 1px 2px rgba(0,0,0,.05),0 6px 20px rgba(0,0,0,.06);
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  background:var(--bg-chirho);color:var(--ink-chirho);line-height:1.5;font-size:16px}
a{color:var(--brand-chirho);text-decoration:none}
a:hover{text-decoration:underline}
h1,h2,h3{line-height:1.2;margin:0 0 .5em}
h1{font-size:1.875rem;font-weight:700}
h2{font-size:1.375rem;font-weight:650}
h3{font-size:1.125rem;font-weight:600}
p{margin:0 0 1rem}
small,.small-chirho{font-size:.875rem}
.muted-chirho{color:var(--muted-chirho)}
.center-chirho{text-align:center}
.container-chirho{max-width:64rem;margin:0 auto;padding:1.5rem}
.narrow-chirho{max-width:34rem;margin:0 auto}
.stack-chirho>*+*{margin-top:1rem}
.row-chirho{display:flex;gap:.75rem;align-items:center;flex-wrap:wrap}
.between-chirho{display:flex;gap:1rem;align-items:center;justify-content:space-between;flex-wrap:wrap}
.grid-chirho{display:grid;gap:1rem;grid-template-columns:repeat(auto-fit,minmax(15rem,1fr))}
.topbar-chirho{background:var(--surface-chirho);border-bottom:1px solid var(--border-chirho)}
.topbar-inner-chirho{max-width:64rem;margin:0 auto;padding:.85rem 1.5rem;display:flex;align-items:center;justify-content:space-between;gap:1rem}
.brand-chirho{font-weight:700;font-size:1.1rem;color:var(--ink-chirho)}
.card-chirho{background:var(--surface-chirho);border:1px solid var(--border-chirho);border-radius:var(--radius-chirho);box-shadow:var(--shadow-chirho);padding:1.25rem}
.btn-chirho{display:inline-flex;align-items:center;gap:.4rem;font:inherit;font-weight:600;line-height:1;
  padding:.6rem 1rem;border-radius:var(--radius-chirho);border:1px solid var(--border-chirho);cursor:pointer;
  background:#eef0f3;color:var(--ink-chirho);transition:filter .12s,box-shadow .12s}
.btn-chirho:hover{filter:brightness(.97);text-decoration:none}
.btn-chirho:focus-visible{outline:2px solid var(--brand-chirho);outline-offset:2px}
.btn-primary-chirho{background:var(--brand-chirho);color:var(--brand-ink-chirho);border-color:transparent}
.btn-ghost-chirho{background:transparent}
.field-chirho{display:block;margin-bottom:.9rem}
.label-chirho{display:block;font-weight:600;font-size:.9rem;margin-bottom:.3rem}
.input-chirho{width:100%;font:inherit;padding:.6rem .7rem;border:1px solid var(--border-chirho);border-radius:var(--radius-chirho);background:#fff;color:var(--ink-chirho)}
.input-chirho:focus{outline:none;border-color:var(--brand-chirho);box-shadow:0 0 0 3px var(--brand-weak-chirho)}
textarea.input-chirho{min-height:6rem;resize:vertical}
.alert-chirho{padding:.7rem .9rem;border-radius:var(--radius-chirho);border:1px solid var(--border-chirho)}
.alert-ok-chirho{background:#f0fdf4;border-color:#bbf7d0;color:#166534}
.alert-err-chirho{background:#fef2f2;border-color:#fecaca;color:#991b1b}
.alert-info-chirho{background:#eff6ff;border-color:#bfdbfe;color:#1e40af}
.table-chirho{width:100%;border-collapse:collapse}
.table-chirho th,.table-chirho td{text-align:left;padding:.55rem .6rem;border-bottom:1px solid var(--border-chirho)}
.table-chirho th{font-size:.78rem;text-transform:uppercase;letter-spacing:.03em;color:var(--muted-chirho)}
.badge-chirho{display:inline-block;font-size:.75rem;font-weight:600;padding:.15rem .55rem;border-radius:999px;background:#eef0f3;color:var(--muted-chirho)}
.badge-ok-chirho{background:#dcfce7;color:#166534}
"#;
