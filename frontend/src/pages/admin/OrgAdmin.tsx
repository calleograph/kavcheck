import { useEffect, useState, type FormEvent } from "react";
import { api, type ApiError } from "../../api";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { SkelRows } from "../../components/ui";

const MAX_LOGO = 300 * 1024;
type Org = { full_name: string; short_name: string; unit: string; contact_email: string; contacts: string; classification: string; footnote: string; signature: string; logo: string; show_logo: boolean };

/** Данные организации для шапок и подвалов всех отчётов (HTML, Excel, печать, письма). Пустые поля в отчёты не попадают. */
export default function OrgAdmin() {
  const [v, setV] = useState<Org | null>(null); const [base, setBase] = useState(""); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [toast, show] = useToast();
  useEffect(() => { api.admin.settings("organization").then((x) => { setV(x as unknown as Org); setBase(JSON.stringify(x)); }).catch((e) => setErr((e as ApiError).message)); }, []);
  if (!v) return <div className="card">{err ? <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div> : <SkelRows rows={4} cols={2} />}</div>;
  const set = <K extends keyof Org>(k: K, x: Org[K]) => setV({ ...v, [k]: x });
  const dirty = base !== JSON.stringify(v);
  const save = async (e: FormEvent) => { e.preventDefault(); setErr(""); setBusy(true); try { const x = await api.admin.saveSettings("organization", v as unknown as Record<string, string | boolean>); setV(x as unknown as Org); setBase(JSON.stringify(x)); show("Данные организации сохранены"); } catch (y) { setErr((y as ApiError).message); } finally { setBusy(false); } };
  const pickLogo = (f: File | undefined) => {
    if (!f) return;
    if (!/^image\/(png|jpeg|webp)$/.test(f.type)) { setErr("Логотип: допустимы PNG, JPEG и WebP"); return; }
    if (f.size > MAX_LOGO) { setErr(`Логотип больше ${MAX_LOGO / 1024} КБ: уменьшите изображение (достаточно высоты 80–120 пикселей)`); return; }
    const r = new FileReader(); r.onload = () => { setErr(""); set("logo", String(r.result)); }; r.readAsDataURL(f);
  };
  const name = v.short_name || v.full_name;
  return (
    <form className="card form" onSubmit={save}>
      <h2>Организация и оформление отчётов</h2>
      <p className="muted small lead-in">Сведения попадают в шапку и подвал HTML и Excel, печатную версию и письма рассылки. Все поля необязательны; незаполненные в отчётах не показываются. Хранятся во внутренней базе KAV Checker.</p>
      <div className="cols"><label>Полное наименование<input value={v.full_name} maxLength={300} onChange={(e) => set("full_name", e.target.value)} placeholder="Общество с ограниченной ответственностью «Пример»" /></label>
        <label>Краткое наименование<input value={v.short_name} maxLength={120} onChange={(e) => set("short_name", e.target.value)} placeholder="ООО «Пример»" /></label></div>
      <div className="cols"><label>Подразделение или служба, формирующая отчёты<input value={v.unit} maxLength={200} onChange={(e) => set("unit", e.target.value)} placeholder="Служба информационной безопасности" /></label>
        <label>Внутренняя классификация документа<input value={v.classification} maxLength={80} onChange={(e) => set("classification", e.target.value)} placeholder="Для внутреннего пользования" /></label></div>
      <div className="cols"><label>Контактный адрес электронной почты<input type="email" value={v.contact_email} maxLength={254} onChange={(e) => set("contact_email", e.target.value)} placeholder="ib@example.local" /></label>
        <label>Другие контакты<input value={v.contacts} maxLength={500} onChange={(e) => set("contacts", e.target.value)} placeholder="тел. 1234, кабинет 305, пн–пт 9:00–18:00" /></label></div>
      <label>Стандартное примечание в конце отчёта<textarea rows={2} value={v.footnote} maxLength={600} onChange={(e) => set("footnote", e.target.value)} placeholder="Документ предназначен для служебного пользования. Копирование без согласования не допускается." /></label>
      <label>Подпись составителя<input value={v.signature} maxLength={200} onChange={(e) => set("signature", e.target.value)} placeholder="Составил: отдел информационной безопасности" /></label>
      <div className="field">Логотип
        <div className="row">{v.logo && <img className="logo-prev" src={v.logo} alt="Предпросмотр логотипа" />}
          <label className="btn" style={{ cursor: "pointer" }}><Icon name="upload" />{v.logo ? "Заменить" : "Загрузить"}<input type="file" accept="image/png,image/jpeg,image/webp" hidden onChange={(e) => pickLogo(e.target.files?.[0])} /></label>
          {v.logo && <button type="button" className="btn ghost" onClick={() => set("logo", "")}>Убрать</button>}
          <label className="check"><input type="checkbox" className="switch" checked={v.show_logo} onChange={(e) => set("show_logo", e.target.checked)} />Показывать в отчётах</label></div>
        <span className="help">PNG, JPEG или WebP до {MAX_LOGO / 1024} КБ. Логотип встраивается в HTML-отчёты и письма; в Excel выводится только название организации.</span></div>
      <h3>Как это выглядит в шапке отчёта</h3>
      <div className="org-prev">{name || v.logo ? <div className="row">{v.logo && v.show_logo && <img className="logo-prev" src={v.logo} alt="" />}<div><div className="on">{name || "—"}</div>
        <div className="muted small">{[v.short_name ? v.full_name : "", v.unit].filter(Boolean).join(" · ")}</div></div>{v.classification && <span className="badge outline" style={{ marginLeft: "auto" }}>{v.classification}</span>}</div>
        : <span className="muted">Данные не заполнены: отчёты формируются с заголовком «KAV Checker» без шапки организации.</span>}
        {(v.footnote || v.signature || v.contact_email) && <div className="muted small" style={{ marginTop: 8 }}>{[v.footnote, v.signature, v.contact_email, v.contacts].filter(Boolean).join(" · ")}</div>}</div>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <div className="form-actions"><button className="btn primary" aria-busy={busy} disabled={!dirty}><span>Сохранить</span></button>{dirty && <><button type="button" className="btn ghost" onClick={() => setV(JSON.parse(base))}>Отменить изменения</button><span className="badge warn">есть несохранённые изменения</span></>}</div>
      {toast}
    </form>
  );
}
