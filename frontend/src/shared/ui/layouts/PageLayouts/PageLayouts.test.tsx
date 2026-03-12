import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import * as PageLayouts from "./index";

import { AppContainer } from "./PageContainer";
import { AppHeader } from "./PageHeader";
import { PageMain } from "./PageMain";
import { PageSidebar } from "./PageSidebar";
import { PageWrapper } from "./PageWrapper";

const { PageLayout } = PageLayouts;

describe("PageLayout", () => {
  describe("AppContainer", () => {
    /**
     * @description Renders AppContainer with children
     * @scenario Mounting AppContainer with child content
     * @expected Container renders with page__container class and displays children
     */
    it("renders correctly", () => {
      const { container } = render(
        <AppContainer>
          <div data-testid="child">Test Content</div>
        </AppContainer>,
      );
      expect(screen.getByTestId("child")).toBeInTheDocument();
      expect(container.firstChild).toHaveClass("page__container");
    });

    /**
     * @description AppContainer applies custom className
     * @scenario Passing additional className to AppContainer
     * @expected Root element has both base and custom classes via classnames
     */
    it("applies custom className", () => {
      const customClass = "custom-class";
      const { container } = render(
        <AppContainer className={customClass}>
          <div>Test</div>
        </AppContainer>,
      );
      expect(container.firstChild).toHaveClass("page__container", customClass);
    });
  });

  // ===========================================================================

  describe("AppHeader", () => {
    /**
     * @description Renders AppHeader with children
     * @scenario Mounting AppHeader with header content
     * @expected Header renders with page__header class and displays children
     */
    it("renders correctly", () => {
      render(
        <AppHeader>
          <h1>Header Title</h1>
        </AppHeader>,
      );
      expect(screen.getByRole("heading")).toBeInTheDocument();
      const header = screen.getByRole("banner");
      expect(header).toHaveClass("page__header");
    });

    /**
     * @description AppHeader applies custom className
     * @scenario Passing additional className to AppHeader
     * @expected Header has base and custom classes
     */
    it("applies custom className", () => {
      const customClass = "header-custom";
      render(<AppHeader className={customClass}>Content</AppHeader>);
      expect(screen.getByRole("banner")).toHaveClass(
        "page__header",
        customClass,
      );
    });
  });

  // ===========================================================================

  describe("PageMain", () => {
    /**
     * @description Renders PageMain with children
     * @scenario Mounting PageMain with main content
     * @expected Main renders with page__main class and semantic main role
     */
    it("renders correctly", () => {
      render(
        <PageMain>
          <article>Main Content</article>
        </PageMain>,
      );
      expect(screen.getByRole("main")).toBeInTheDocument();
      expect(screen.getByRole("main")).toHaveClass("page__main");
    });

    /**
     * @description PageMain applies custom className
     * @scenario Passing className prop to PageMain
     * @expected Combines page__main with custom class
     */
    it("applies custom className", () => {
      const customClass = "main-custom";
      render(<PageMain className={customClass}>Content</PageMain>);
      expect(screen.getByRole("main")).toHaveClass("page__main", customClass);
    });
  });

  // ===========================================================================

  describe("PageSidebar", () => {
    /**
     * @description PageSidebar renders static content
     * @scenario Mounting PageSidebar
     * @expected Renders page-sidebar class and "AppSidebar" text
     */
    it("renders static content", () => {
      render(<PageSidebar />);
      const sidebar = screen.getByText("AppSidebar");
      expect(sidebar).toBeInTheDocument();
      expect(sidebar.closest("div")).toHaveClass("page-sidebar");
    });
  });

  // ===========================================================================

  describe("PageWrapper", () => {
    /**
     * @description Renders PageWrapper with children
     * @scenario Mounting PageWrapper
     * @expected Wrapper div with page__wrapper class containing children
     */
    it("renders correctly", () => {
      render(
        <PageWrapper>
          <section>Wrapped content</section>
        </PageWrapper>,
      );
      const wrapperEl = screen
        .getByText("Wrapped content")
        .closest("div") as Element;
      expect(wrapperEl).toHaveClass("page__wrapper");
    });

    /**
     * @description PageWrapper applies custom className
     * @scenario Passing className to PageWrapper
     * @expected Combines page__wrapper and custom classes
     */
    it("applies custom className", () => {
      const customClass = "wrapper-custom";
      render(<PageWrapper className={customClass}>Content</PageWrapper>);
      const wrapperEl = screen.getByText("Content").closest("div") as Element;
      expect(wrapperEl).toHaveClass("page__wrapper", customClass);
    });
  });

  // ===========================================================================

  describe("PageLayout", () => {
    /**
     * @description PageLayout renders base structure
     * @scenario Rendering PageLayout root with children
     * @expected Root div with "page" className
     */
    it("renders base structure", () => {
      render(<PageLayout>Test Page</PageLayout>);
      const root = screen.getByText("Test Page").closest("div") as Element;
      expect(root).toHaveClass("page");
    });

    /**
     * @description PageLayout applies custom className
     * @scenario Passing className to PageLayout root
     * @expected Combines "page" with custom className
     */
    it("applies custom className", () => {
      const customClass = "page-custom";
      render(<PageLayout className={customClass}>Content</PageLayout>);
      const root = screen.getByText("Content").closest("div") as Element;
      expect(root).toHaveClass("page", customClass);
    });

    /**
     * @description PageLayout static members are accessible
     * @scenario Accessing PageLayout.Header, Main, etc. static components
     * @expected All subcomponents: Header, Main, Container, Sidebar, Wrapper are exported and renderable
     */
    it.each([
      ["Header", "Header"],
      ["Main", "Main"],
      ["Container", "Container"],
      ["Sidebar", null],
      ["Wrapper", "Wrapper"],
    ])("static member %s renders correctly", (name, content) => {
      const Component = PageLayout[name as keyof typeof PageLayout];
      expect(Component).toBeDefined();
      render(<Component>{content}</Component>);
    });

    /**
     * @description Full PageLayout compound usage
     * @scenario Using PageLayout with all subcomponents in typical layout
     * @expected All components render with correct hierarchy and classes
     */
    it("renders full compound layout", () => {
      render(
        <PageLayout className="test-page">
          <PageLayout.Header>
            <h1>App Header</h1>
          </PageLayout.Header>
          <PageLayout.Wrapper>
            <PageLayout.Container>
              <PageLayout.Main className="custom-main">
                Main Content
              </PageLayout.Main>
            </PageLayout.Container>
            <PageLayout.Sidebar />
          </PageLayout.Wrapper>
        </PageLayout>,
      );

      expect(screen.getByRole("heading")).toBeInTheDocument();
      expect(screen.getByRole("main")).toHaveClass("page__main", "custom-main");
      expect(screen.getByText("AppSidebar")).toBeInTheDocument();
      const mainContainer = screen
        .getByText("Main Content")
        .closest("div") as Element;
      expect(mainContainer).toHaveClass("page__container");
    });
  });
});
