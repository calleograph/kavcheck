/** Камера с распознаванием QR и штрихкодов средствами браузера (BarcodeDetector). Без внешних библиотек; если браузер не умеет — остаётся ввод (ручные сканеры работают как клавиатура). */
import { useEffect, useRef, useState } from "react";

type Detector = { detect: (src: CanvasImageSource) => Promise<{ rawValue: string }[]> };
export const hasDetector = () => typeof window !== "undefined" && "BarcodeDetector" in window;

export function Camera({ on, onCode, onError }: { on: boolean; onCode: (code: string) => void; onError: (msg: string) => void }) {
  const video = useRef<HTMLVideoElement>(null);
  const cb = useRef(onCode); cb.current = onCode;
  const [ready, setReady] = useState(false);
  useEffect(() => {
    if (!on) return;
    let stream: MediaStream | null = null; let timer = 0; let alive = true;
    (async () => {
      try {
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
        if (!video.current || !alive) return;
        video.current.srcObject = stream; await video.current.play(); setReady(true);
        const Det = (window as unknown as { BarcodeDetector: new (o: { formats: string[] }) => Detector }).BarcodeDetector;
        const det = new Det({ formats: ["qr_code", "code_128", "ean_13", "code_39", "data_matrix"] });
        const tick = async () => { if (!alive || !video.current) return; try { const r = await det.detect(video.current); if (r[0]?.rawValue) cb.current(r[0].rawValue); } catch { /* кадр не распознан */ } timer = window.setTimeout(() => void tick(), 350); };
        void tick();
      } catch (e) { onError(`Камера недоступна: ${(e as Error).message}. Разрешите доступ к камере или используйте поле ввода.`); }
    })();
    return () => { alive = false; setReady(false); window.clearTimeout(timer); stream?.getTracks().forEach((t) => t.stop()); };
  }, [on]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!on) return null;
  return <div className="inv-cam"><video ref={video} muted playsInline aria-label="Изображение с камеры" />{ready && <span className="inv-cam-frame" aria-hidden />}</div>;
}
