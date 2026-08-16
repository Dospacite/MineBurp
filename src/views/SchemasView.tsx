import { Check, FileJson } from "lucide-react";
import { useState } from "react";

import { desktop } from "../lib/desktop";
import { message } from "../hooks/useMineBurp";

const starter = `{
  "manifest": {
    "id": "assessment.example",
    "name": "Example plugin channels",
    "version": "1.0.0",
    "minecraft_versions": ["1.21.1"],
    "loaders": ["fabric"]
  },
  "schemas": []
}`;

export function SchemasView({ onError }: { onError: (error: string) => void }) {
  const [schema, setSchema] = useState(starter);
  const [valid, setValid] = useState(false);

  async function validate() {
    try {
      await desktop.schemaValidate(schema);
      setValid(true);
    } catch (reason) {
      setValid(false);
      onError(message(reason));
    }
  }

  return (
    <div className="schema-layout">
      <section>
        <div className="page-heading"><span className="eyebrow">Declarative decoding</span><h1>Schema workbench</h1><p>Describe custom payloads without running plugin or mod code inside MineBurp.</p></div>
        <div className="schema-toolbar"><span><FileJson size={15} /> JSON schema pack</span><button className="button primary" onClick={validate}>{valid ? <Check size={14} /> : null} Validate &amp; load</button></div>
        <textarea className="schema-editor" spellCheck={false} value={schema} onChange={(event) => { setSchema(event.target.value); setValid(false); }} />
      </section>
      <aside className="schema-reference"><span className="eyebrow">Field types</span><h2>Portable and bounded</h2><p>Schemas support numeric primitives, VarInt, VarLong, UUID, strings, byte blocks, arrays, and nested structs.</p><p className="muted">Depth and collection limits are enforced before decode. Schema packs never load native libraries or scripts.</p></aside>
    </div>
  );
}
