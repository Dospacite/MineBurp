import { ChevronDown, ChevronRight } from "lucide-react";
import { memo, useEffect, useMemo, useRef, useState } from "react";

import type { FieldSpan, PacketLayout } from "../domain/types";
import { t } from "../i18n";

interface TreeNode {
  key: string;
  label: string;
  field: FieldSpan | null;
  offset: number;
  end: number;
  children: TreeNode[];
}

/**
 * The frame's fields with the bytes each one occupies.
 *
 * Built from `packet_layout`, so every row carries an offset and a length:
 * picking a row marks its bytes in the hex view, and picking a byte there
 * marks the innermost field holding it here. Dotted names (`position.x`)
 * nest under their parent; flat names stay one level deep.
 */
export const FieldTree = memo(function FieldTree({
  layout,
  selected,
  onSelect,
}: {
  layout: PacketLayout | null;
  /** The span currently marked, as `offset:length`. */
  selected: string | null;
  onSelect: (field: FieldSpan) => void;
}) {
  const tree = useMemo(() => buildTree(layout?.fields ?? []), [layout]);
  const container = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!selected) return;
    container.current?.querySelector(`[data-span="${selected}"]`)?.scrollIntoView?.({ block: "nearest" });
  }, [selected]);

  if (!layout || layout.fields.length === 0) {
    return <p className="decoded-empty">{t("structure.none")}</p>;
  }

  return (
    <div className="field-tree" role="tree" aria-label={t("structure.title")} ref={container}>
      {tree.map((node, index) => (
        <TreeRow
          key={node.key}
          node={node}
          depth={0}
          selected={selected}
          onSelect={onSelect}
          tabStop={index === 0 && !hasSelection(tree, selected)}
        />
      ))}
      {!layout.complete && <p className="field-tree-note">{t("structure.partial")}</p>}
    </div>
  );
});

function TreeRow({
  node,
  depth,
  selected,
  onSelect,
  tabStop = false,
}: {
  node: TreeNode;
  depth: number;
  selected: string | null;
  onSelect: (field: FieldSpan) => void;
  /** Holds the tree's tab stop while no row is selected. */
  tabStop?: boolean;
}) {
  const [open, setOpen] = useState(true);
  const span = `${node.offset}:${node.end - node.offset}`;
  const isSelected = node.field !== null && selected === `${node.field.offset}:${node.field.length}`;
  const pick = () => {
    if (node.field) onSelect(node.field);
    else onSelect(groupSpan(node));
  };

  return (
    <>
      <div
        className={`field-tree-row ${isSelected ? "selected" : ""}`}
        role="treeitem"
        aria-selected={isSelected}
        aria-expanded={node.children.length > 0 ? open : undefined}
        aria-level={depth + 1}
        tabIndex={isSelected || tabStop ? 0 : -1}
        data-span={node.field ? `${node.field.offset}:${node.field.length}` : span}
        style={{ paddingLeft: 8 + depth * 14 }}
        onClick={pick}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            pick();
          } else if (event.key === "ArrowRight" && node.children.length > 0) setOpen(true);
          else if (event.key === "ArrowLeft" && node.children.length > 0) setOpen(false);
          else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
            event.preventDefault();
            const rows = Array.from(
              event.currentTarget
                .closest("[role='tree']")
                ?.querySelectorAll<HTMLElement>("[role='treeitem']") ?? [],
            );
            const index = rows.indexOf(event.currentTarget);
            rows[index + (event.key === "ArrowDown" ? 1 : -1)]?.focus();
          }
        }}
      >
        {node.children.length > 0 ? (
          <button
            type="button"
            className="field-tree-toggle"
            tabIndex={-1}
            aria-label={open ? t("structure.collapse") : t("structure.expand")}
            onClick={(event) => {
              event.stopPropagation();
              setOpen(!open);
            }}
          >
            {open ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
          </button>
        ) : (
          <span className="field-tree-toggle" aria-hidden="true" />
        )}
        <span className="field-tree-name">{node.label}</span>
        <span className="field-tree-value" title={node.field ? valueText(node.field) : undefined}>
          {node.field ? valueText(node.field) : ""}
        </span>
        <span className="field-tree-kind">{node.field?.kind ?? ""}</span>
        <span className="field-tree-offset">
          0x{node.offset.toString(16)}+{node.end - node.offset}
        </span>
      </div>
      {open &&
        node.children.map((child) => (
          <TreeRow key={child.key} node={child} depth={depth + 1} selected={selected} onSelect={onSelect} />
        ))}
    </>
  );
}

function hasSelection(nodes: TreeNode[], selected: string | null): boolean {
  if (!selected) return false;
  return nodes.some(
    (node) =>
      (node.field !== null && `${node.field.offset}:${node.field.length}` === selected) ||
      hasSelection(node.children, selected),
  );
}

function valueText(field: FieldSpan): string {
  if (field.value === null) return field.kind === "bytes" || field.kind === "prefixed_bytes" ? "…" : "—";
  const text = String(field.value);
  return text.length > 120 ? `${text.slice(0, 120)}…` : text;
}

function groupSpan(node: TreeNode): FieldSpan {
  return {
    name: node.label,
    kind: "bytes",
    offset: node.offset,
    length: node.end - node.offset,
    value: null,
  };
}

export function buildTree(fields: FieldSpan[]): TreeNode[] {
  const roots: TreeNode[] = [];
  const groups = new Map<string, TreeNode>();
  fields.forEach((field, index) => {
    const parts = field.name.split(".").filter(Boolean);
    let siblings = roots;
    let path = "";
    for (const [depth, part] of parts.entries()) {
      path = path ? `${path}.${part}` : part;
      const leaf = depth === parts.length - 1;
      if (leaf) {
        siblings.push({
          key: `${index}:${path}`,
          label: part,
          field,
          offset: field.offset,
          end: field.offset + field.length,
          children: [],
        });
        break;
      }
      let group = groups.get(path);
      if (!group) {
        group = {
          key: `group:${path}`,
          label: part,
          field: null,
          offset: field.offset,
          end: field.offset,
          children: [],
        };
        groups.set(path, group);
        siblings.push(group);
      }
      group.offset = Math.min(group.offset, field.offset);
      group.end = Math.max(group.end, field.offset + field.length);
      siblings = group.children;
    }
  });
  return roots;
}

/** The innermost field holding `offset`, as `offset:length`. */
export function fieldAt(fields: FieldSpan[], offset: number): FieldSpan | null {
  let best: FieldSpan | null = null;
  for (const field of fields) {
    if (offset < field.offset || offset >= field.offset + field.length) continue;
    if (!best || field.length < best.length) best = field;
  }
  return best;
}
