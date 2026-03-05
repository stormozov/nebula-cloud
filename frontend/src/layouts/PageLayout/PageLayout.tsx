import { PageFooter, PageHeader, PageMain, PageSidebar } from "@/layouts";

import "./PageLayout.scss";

/**
 * Main page layout component.
 */
export default function PageLayout() {
	return (
		<div className="page-layout">
			<PageHeader />

			<div className="page-content-wrap">
				<PageSidebar />
				<PageMain />
			</div>

			<PageFooter />
		</div>
	);
}
