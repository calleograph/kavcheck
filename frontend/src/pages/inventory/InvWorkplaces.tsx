import { useSearchParams } from "react-router-dom";
import { WorkplaceReview } from "../../components/WorkplaceReview";
import { BackLink } from "../../components/ui";

export default function InvWorkplaces() {
  const [params] = useSearchParams();
  const assetId = params.get("asset_id") ?? undefined;
  return <div className="inv-page">
    {assetId && <BackLink to={`/inventory/assets/${encodeURIComponent(assetId)}?tab=place`} label="Расположение и ответственные" />}
    <div className="inv-head"><h1>Рабочие места</h1></div>
    <WorkplaceReview inventory assetId={assetId} />
  </div>;
}
