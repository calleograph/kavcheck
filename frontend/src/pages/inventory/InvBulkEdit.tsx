import { useCallback, useState, type ReactNode } from "react";
import type { ApiError } from "../../api";
import { Modal } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { TagInput } from "../../components/ui";
import { num } from "../../util";
import { InvZoneSelect, LocationPicker, PersonPicker, PropField, RefSelect, useInv } from "./InvBits";
import { inv, type BulkResult, type BulkSelection, type Perm, type Prop } from "./invApi";

export function toggleAssetMarks(marks: ReadonlySet<number>, ids: number[], whole: boolean): Set<number> {
  const select = ids.some((id) => marks.has(id) === whole);
  const next = new Set(marks);
  for (const id of ids) {
    if (select !== whole) next.add(id);
    else next.delete(id);
  }
  return next;
}

export function filtersForBulk(params: Record<string, string>): Record<string, string | Record<string, string>> {
  const ordinary = Object.entries(params).filter(([key]) => !key.startsWith("p."));
  const props = Object.fromEntries(Object.entries(params).filter(([key]) => key.startsWith("p.")).map(([key, value]) => [key.slice(2), value]));
  return { ...Object.fromEntries(ordinary), props };
}

type Kind = "ref" | "location" | "person" | "zone" | "tags" | "bool" | "text" | "date" | "money" | "unit" | "note" | "prop";
interface Field { key: string; label: string; kind: Kind; perm?: Perm; maxLength?: number; prop?: Prop }
const FIELDS: Field[] = [
  { key: "dept_id", label: "Подразделение", kind: "ref" },
  { key: "branch_id", label: "Филиал", kind: "ref" },
  { key: "zone_id", label: "Зона ответственности", kind: "zone" },
  { key: "location_id", label: "Учётное местоположение", kind: "location", perm: "location" },
  { key: "loc_detail", label: "Уточнение местоположения", kind: "text", perm: "location", maxLength: 300 },
  { key: "resp_id", label: "Ответственный", kind: "person", perm: "people" },
  { key: "user_id", label: "Пользователь", kind: "person", perm: "people" },
  { key: "owner_id", label: "Владелец", kind: "person", perm: "people" },
  { key: "mol_id", label: "Материально ответственное лицо", kind: "person", perm: "people" },
  { key: "it_id", label: "Ответственный ИТ-специалист", kind: "person", perm: "people" },
  { key: "type_id", label: "Тип оборудования", kind: "ref" },
  { key: "status_id", label: "Статус", kind: "ref" },
  { key: "tags", label: "Теги", kind: "tags" },
  { key: "purpose", label: "Назначение", kind: "text", maxLength: 500 },
  { key: "service", label: "Сервис или система", kind: "text", maxLength: 300 },
  { key: "name", label: "Наименование", kind: "text", maxLength: 300 },
  { key: "manufacturer_id", label: "Производитель", kind: "ref" },
  { key: "model_id", label: "Модель", kind: "ref" },
  { key: "acc_no", label: "Бухгалтерский номер", kind: "text", maxLength: 60 },
  { key: "supplier_id", label: "Поставщик", kind: "ref" },
  { key: "purchase_date", label: "Дата приобретения", kind: "date" },
  { key: "received_date", label: "Дата поступления", kind: "date" },
  { key: "commissioned_date", label: "Ввод в эксплуатацию", kind: "date" },
  { key: "warranty_until", label: "Гарантия до", kind: "date" },
  { key: "cost", label: "Стоимость, ₽", kind: "money" },
  { key: "purchase_doc", label: "Документ приобретения", kind: "text", maxLength: 300 },
  { key: "rack_unit", label: "Нижний юнит в стойке", kind: "unit" },
  { key: "rack_units", label: "Высота в стойке, юнитов", kind: "unit" },
  { key: "no_count", label: "Не подлежит инвентаризации", kind: "bool" },
  { key: "note", label: "Примечание", kind: "note" },
];
const isEmpty = (value: unknown) => value == null || (typeof value === "string" && !value.trim()) || (Array.isArray(value) && !value.length);
const asId = (value: unknown) => typeof value === "number" ? value : null;

export function InvBulkEdit({ selection, count, onClose, onDone }: { selection: BulkSelection; count: number; onClose: () => void; onDone: (n: number) => void }) {
  const { meta, can } = useInv();
  const [draft, setDraft] = useState<Record<string, unknown>>({});
  const [people, setPeople] = useState<Record<string, string>>({});
  const [onlyEmpty, setOnlyEmpty] = useState(false);
  const [comment, setComment] = useState("");
  const [plan, setPlan] = useState<BulkResult | null>(null);
  const [result, setResult] = useState<BulkResult | null>(null);
  const [busy, setBusy] = useState<"check" | "apply" | null>(null);
  const [error, setError] = useState("");
  const fields = [...FIELDS, ...meta.props.filter((p) => p.active).map((prop): Field => ({ key: `props.${prop.code}`, label: prop.name, prop, kind: "prop" }))]
    .filter((f) => can(f.perm ?? "edit"));
  const chosen = fields.filter((f) => Object.hasOwn(draft, f.key));
  const ready = chosen.length > 0 && chosen.every(({ key }) => draft[key] !== undefined && (!onlyEmpty || !isEmpty(draft[key])));
  const invalidate = () => { setPlan(null); setError(""); };
  const change = (key: string, value: unknown) => { setDraft((d) => ({ ...d, [key]: value })); invalidate(); };
  const remove = (key: string) => { setDraft((d) => { const next = { ...d }; delete next[key]; return next; }); invalidate(); };
  const close = useCallback(() => {
    if (busy) return;
    if (result) onDone(result.changed ?? 0);
    else onClose();
  }, [busy, result, onClose, onDone]);

  const run = async (dryRun: boolean) => {
    setBusy(dryRun ? "check" : "apply"); setError("");
    const data = Object.fromEntries(chosen.filter((f) => !f.prop).map(({ key }) => [key, draft[key]]));
    const props = Object.fromEntries(chosen.filter((f) => f.prop).map(({ key, prop }) => [prop!.code, draft[key]]));
    if (Object.keys(props).length) data.props = props;
    try {
      const response = await inv.bulk(selection, data, comment, dryRun, { only_empty: onlyEmpty, preview_token: dryRun ? undefined : plan?.preview_token });
      if (dryRun) setPlan(response);
      else if (response.error_count || response.missing) setResult(response);
      else onDone(response.changed ?? 0);
    } catch (e) { setError((e as ApiError).message); setPlan(null); }
    finally { setBusy(null); }
  };

  const input = (field: Field): ReactNode => {
    const { key, label, kind, maxLength } = field;
    const value = draft[key], setValue = (v: unknown) => change(key, v);
    if (kind === "ref") return <RefSelect kind={key.slice(0, -3)} label={label} value={asId(value)} onChange={setValue}
      parent={key === "model_id" ? asId(draft.manufacturer_id) : undefined} empty={value === null ? "Будет очищено" : "Выберите значение"} />;
    if (kind === "location") return <LocationPicker label={label} value={asId(value)} onChange={setValue} placeholder={value === null ? "Будет очищено" : "Выберите узел дерева"} />;
    if (kind === "person") return <PersonPicker label={label} value={asId(value)} name={people[key]} onChange={(id, name) => { setPeople((p) => ({ ...p, [key]: name })); setValue(id); }} />;
    if (kind === "zone") return <InvZoneSelect value={typeof value === "string" ? value : null} onChange={setValue} empty={value === null ? "Будет очищено" : "Выберите значение"} />;
    if (kind === "tags") return <div className="field"><span className="field-label">{label}</span>
      <TagInput label={label} value={Array.isArray(value) ? value : []} onChange={setValue} placeholder="Введите тег" mono={false} /></div>;
    if (kind === "bool" || field.prop?.type === "bool") return <label className="field">{label}<select value={typeof value === "boolean" ? String(value) : ""} onChange={(e) => setValue(e.target.value === "" ? undefined : e.target.value === "true")}>
      <option value="">Выберите значение</option><option value="true">Да</option><option value="false">Нет</option></select></label>;
    if (field.prop) return <PropField p={field.prop} value={value} onChange={setValue} />;
    const editText = (text: string) => setValue(text || null);
    if (kind === "note") return <label className="field">{label}<textarea rows={3} maxLength={20000} value={String(value ?? "")} onChange={(e) => editText(e.target.value)} /></label>;
    return <label className="field">{label}<input type={kind === "date" ? "date" : kind === "unit" ? "number" : "text"} value={String(value ?? "")} onChange={(e) => editText(e.target.value)}
      maxLength={maxLength} inputMode={kind === "money" ? "decimal" : undefined} min={kind === "unit" ? 1 : undefined} max={kind === "unit" ? 60 : undefined} /></label>;
  };

  return (
    <Modal title="Массовое редактирование" wide lede={"filters" in selection ? `По текущим фильтрам выбрано ${num(count)}` : `Выбрано карточек: ${num(count)}`} onClose={close}
      footer={result ? <button className="btn primary" onClick={close}>Готово</button>
        : <><button className="btn" disabled={!!busy} onClick={close}>Отмена</button><div className="spacer" />
          <button className="btn" disabled={!!busy || !ready} aria-busy={busy === "check"} onClick={() => void run(true)}>{busy === "check" ? "Проверяем…" : "Проверить"}</button>
          <button className="btn primary" disabled={!!busy || !plan?.would_change || !plan.preview_token} aria-busy={busy === "apply"} onClick={() => void run(false)}>
            {busy === "apply" ? "Применяем…" : `Применить${plan?.would_change ? ` к ${num(plan.would_change)}` : ""}`}</button></>}>
      {!result && <form onSubmit={(e) => e.preventDefault()}>
        <fieldset className="inv-fs form-stack" disabled={!!busy}><legend>Изменяемые свойства</legend>
          <label className="field">Добавить свойство<select value="" onChange={(e) => { if (e.target.value) change(e.target.value, undefined); }}>
            <option value="">Выберите поле</option>{fields.filter((f) => !Object.hasOwn(draft, f.key)).map((f) => <option key={f.key} value={f.key}>{f.label}</option>)}
          </select></label>
          {chosen.map((field) => <div key={field.key} className="row wrap">
            <div className="grow">{input(field)}</div>
            {!onlyEmpty && field.kind !== "bool" && !field.prop?.required && <button className="btn mini" type="button" aria-label={`Очистить поле «${field.label}»`}
              onClick={() => change(field.key, field.kind === "tags" ? [] : null)}>Очистить значение</button>}
            <button className="btn mini icon" type="button" aria-label={`Исключить поле «${field.label}»`} onClick={() => remove(field.key)}><Icon name="close" size={15} /></button>
            {draft[field.key] !== undefined && isEmpty(draft[field.key]) && <span className="muted small">{onlyEmpty ? "Укажите новое значение" : "Значение будет очищено"}</span>}
          </div>)}
          <label className="field">Режим обновления<select value={onlyEmpty ? "empty" : "replace"} onChange={(e) => { setOnlyEmpty(e.target.value === "empty"); invalidate(); }}>
            <option value="replace">Заменить существующие значения</option><option value="empty">Заполнить только пустые поля</option>
          </select></label>
          <label className="field">Основание или комментарий<input value={comment} onChange={(e) => { setComment(e.target.value); invalidate(); }} maxLength={2000} /></label>
        </fieldset>
      </form>}
      {plan && !result && <div className="alert flat" role="status"><Icon name="info" /><div className="alert-body">
        <p>Проверено карточек: {num(plan.found)}. Изменится: {num(plan.would_change ?? 0)}.</p>
        {plan.fields.length > 0 && <p>Свойства: {plan.fields.map((f) => f.label).join(", ")}.</p>}
      </div></div>}
      {result && <p role="status">Изменено карточек: {num(result.changed ?? 0)}.</p>}
      {(result ?? plan) && <BulkErrors result={(result ?? plan)!} />}
      {error && <p className="field-err" role="alert">{error}</p>}
    </Modal>
  );
}

function BulkErrors({ result }: { result: BulkResult }) {
  if (!result.error_count && !result.missing) return null;
  return <div className="alert flat error"><Icon name="alert" /><div className="alert-body">
    {result.missing > 0 && <p>В доступной области отсутствуют карточки: {num(result.missing)}.</p>}
    {result.error_count > 0 && <details open>
      <summary>Карточек с ошибками: {num(result.error_count)}</summary>
      <ul>{result.errors.map((e) => <li key={e.id}>{e.inv_no}: {e.error}</li>)}</ul>
      {result.error_count > result.errors.length && <p className="muted small">Показаны первые {num(result.errors.length)}.</p>}
    </details>}
  </div></div>;
}
