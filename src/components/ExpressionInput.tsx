import { type KeyboardEvent, useEffect, useId, useRef, useState } from "react";

import type { FilterVocabulary } from "../domain/types";
import { applyCompletion, type Completion, completions } from "../lib/expressions";
import { loadVocabulary } from "../lib/vocabulary";

/**
 * A filter-expression field that suggests what the grammar accepts next —
 * field names, then operators, then the closed sets of values — from the
 * vocabulary the backend reports. Arrow keys pick a suggestion; Tab or Enter
 * takes it. Enter with no suggestion open is left to the caller.
 */
export function ExpressionInput({
  value,
  onChange,
  onBlur,
  onEnter,
  placeholder,
  ariaLabel,
  invalid,
  className,
}: {
  value: string;
  onChange: (value: string) => void;
  onBlur?: () => void;
  onEnter?: () => void;
  placeholder?: string;
  ariaLabel: string;
  invalid?: boolean;
  className?: string;
}) {
  const [vocabulary, setVocabulary] = useState<FilterVocabulary | null>(null);
  const [options, setOptions] = useState<Completion[]>([]);
  const [highlight, setHighlight] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const pendingCaret = useRef<number | null>(null);
  const listId = useId();

  useEffect(() => {
    let live = true;
    void loadVocabulary().then((loaded) => live && setVocabulary(loaded));
    return () => {
      live = false;
    };
  }, []);

  // Restore the caret after a completion rewrote the value.
  useEffect(() => {
    if (pendingCaret.current === null || !input.current) return;
    input.current.setSelectionRange(pendingCaret.current, pendingCaret.current);
    pendingCaret.current = null;
  });

  function suggest(text: string, caret: number | null) {
    const next = completions(text, caret ?? text.length, vocabulary);
    setOptions(next);
    setHighlight(0);
  }

  function accept(completion: Completion) {
    const { text, caret } = applyCompletion(value, completion);
    pendingCaret.current = caret;
    onChange(text);
    suggest(text, caret);
  }

  function onKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    const open = options.length > 0;
    if (open && (event.key === "ArrowDown" || event.key === "ArrowUp")) {
      event.preventDefault();
      setHighlight((current) =>
        event.key === "ArrowDown"
          ? (current + 1) % options.length
          : (current - 1 + options.length) % options.length,
      );
      return;
    }
    if (open && (event.key === "Tab" || event.key === "Enter")) {
      const choice = options[highlight];
      if (choice) {
        event.preventDefault();
        accept(choice);
        return;
      }
    }
    if (open && event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      setOptions([]);
      return;
    }
    if (event.key === "Enter") onEnter?.();
  }

  const active = options[highlight];

  return (
    <span className={`expression-input ${className ?? ""}`}>
      <input
        ref={input}
        value={value}
        spellCheck={false}
        autoComplete="off"
        placeholder={placeholder}
        aria-label={ariaLabel}
        aria-invalid={invalid || undefined}
        role="combobox"
        aria-autocomplete="list"
        aria-expanded={options.length > 0}
        aria-controls={listId}
        aria-activedescendant={active ? `${listId}-${highlight}` : undefined}
        onChange={(event) => {
          onChange(event.target.value);
          suggest(event.target.value, event.target.selectionStart);
        }}
        onFocus={(event) => suggest(event.target.value, event.target.selectionStart)}
        onClick={(event) => suggest(event.currentTarget.value, event.currentTarget.selectionStart)}
        onBlur={() => {
          setOptions([]);
          onBlur?.();
        }}
        onKeyDown={onKeyDown}
      />
      {options.length > 0 && (
        <div className="expression-suggestions" role="listbox" id={listId}>
          {options.map((option, index) => (
            <div
              key={option.text}
              tabIndex={-1}
              id={`${listId}-${index}`}
              role="option"
              aria-selected={index === highlight}
              className={index === highlight ? "active" : ""}
              // Pointer-down rather than click: click fires after the input's blur
              // has already closed the list.
              onPointerDown={(event) => {
                event.preventDefault();
                accept(option);
              }}
            >
              {option.text}
            </div>
          ))}
        </div>
      )}
    </span>
  );
}
