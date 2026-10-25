import { Check, FileJson } from "lucide-react";
import { useState } from "react";
import { message } from "../hooks/useMineBurp";
import { t } from "../i18n";
import { desktop } from "../lib/desktop";

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
    <section className="schema-layout">
      <div className="schema-toolbar">
        <span>
          <FileJson size={15} /> {t("schemas.pack")}
        </span>
        <button type="button" className="button primary" onClick={validate}>
          {valid ? <Check size={14} /> : null} {t("schemas.validate")}
        </button>
      </div>
      <textarea
        className="schema-editor"
        spellCheck={false}
        value={schema}
        onChange={(event) => {
          setSchema(event.target.value);
          setValid(false);
        }}
      />
    </section>
  );
}
