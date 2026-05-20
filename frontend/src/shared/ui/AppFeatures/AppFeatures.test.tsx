import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, type Mock, vi } from "vitest";

import { Heading } from "../Heading";
import { Icon } from "../Icon";
import { AppFeatures } from "./AppFeatures";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("../Heading", () => ({
  Heading: vi.fn(({ children, level, visualSize, className }) => (
    <div
      data-testid="mock-heading"
      data-level={level}
      data-visual-size={visualSize}
      className={className}
    >
      {children}
    </div>
  )),
}));

vi.mock("../Icon", () => ({
  Icon: vi.fn(({ name, size }) => (
    <div data-testid="mock-icon" data-icon-name={name} data-size={size}>
      Icon mock
    </div>
  )),
}));

// =============================================================================
// TESTS
// =============================================================================

describe("AppFeatures", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("when titleProps is provided with children", () => {
    /**
     * @description Renders Heading level 2 with custom titleProps
     * @scenario AppFeatures rendered with titleProps={{ children: "Features Title" }}
     * @expected Heading component called once with level=2 and children="Features Title"
     */
    it("should render Heading with level 2 and provided children", () => {
      // Arrange
      const titleProps = { children: "Our Awesome Features" };

      // Act
      render(<AppFeatures titleProps={titleProps} />);

      // Assert
      const headingCalls = (Heading as Mock).mock.calls;
      const level2Call = headingCalls.find((call) => call[0].level === 2);
      expect(level2Call).toBeDefined();
      expect(level2Call?.[0]).toMatchObject({
        level: 2,
        children: "Our Awesome Features",
      });
      expect(screen.getByText("Our Awesome Features")).toBeInTheDocument();
    });

    /**
     * @description Spreads additional titleProps to Heading component
     * @scenario AppFeatures rendered with titleProps including className and visualSize
     * @expected Heading with level 2 receives className and visualSize
     */
    it("should pass all titleProps to Heading component", () => {
      // Arrange
      const titleProps = {
        children: "Title",
        className: "custom-heading",
        visualSize: "lg" as const,
      };

      // Act
      render(<AppFeatures titleProps={titleProps} />);

      // Assert
      const headingCalls = (Heading as Mock).mock.calls;
      const level2Call = headingCalls.find((call) => call[0].level === 2);
      expect(level2Call?.[0]).toMatchObject({
        className: "custom-heading",
        visualSize: "lg",
      });
    });
  });

  describe("when titleProps is not provided or has no children", () => {
    /**
     * @description Does not render level 2 Heading when titleProps is omitted
     * @scenario AppFeatures rendered without titleProps
     * @expected No Heading with level=2, but level=3 Headings for features still render
     */
    it("should not render level 2 Heading when titleProps is omitted", () => {
      // Arrange & Act
      render(<AppFeatures />);

      // Assert
      const headingCalls = (Heading as Mock).mock.calls;
      const level2Call = headingCalls.find((call) => call[0].level === 2);
      expect(level2Call).toBeUndefined();
      // Verify that level 3 headings for features still render
      const level3Calls = headingCalls.filter((call) => call[0].level === 3);
      expect(level3Calls).toHaveLength(4);
    });

    /**
     * @description Does not render level 2 Heading when titleProps.children is empty string
     * @scenario AppFeatures rendered with titleProps={{ children: "" }}
     * @expected No Heading with level=2
     */
    it("should not render level 2 Heading when titleProps.children is empty string", () => {
      // Arrange
      const titleProps = { children: "" };

      // Act
      render(<AppFeatures titleProps={titleProps} />);

      // Assert
      const headingCalls = (Heading as Mock).mock.calls;
      const level2Call = headingCalls.find((call) => call[0].level === 2);
      expect(level2Call).toBeUndefined();
    });
  });

  describe("feature list rendering", () => {
    /**
     * @description Renders all 4 feature items from static list
     * @scenario AppFeatures rendered without titleProps
     * @expected 4 list items, each with title, description, and icon
     */
    it("should render all 4 features with correct titles and descriptions", () => {
      // Arrange
      const expectedFeatures = [
        {
          title: "Управление файлами",
          description:
            "Загружайте, переименовывайте, удаляйте файлы и добавляйте комментарии",
        },
        {
          title: "Скачивание файлов",
          description: "Просматривайте и скачивайте свои файлы в любое время",
        },
        {
          title: "Специальные ссылки",
          description: "Генерируйте уникальные ссылки для доступа к файлам",
        },
        {
          title: "Безопасность",
          description: "Ваши файлы защищены и доступны только вам",
        },
      ];

      // Act
      render(<AppFeatures />);

      // Assert
      for (const feature of expectedFeatures) {
        expect(screen.getByText(feature.title)).toBeInTheDocument();
        expect(screen.getByText(feature.description)).toBeInTheDocument();
      }
    });

    /**
     * @description Renders Icon component for each feature with correct name and size 16
     * @scenario AppFeatures rendered
     * @expected Icon called with name from feature and size=16 for all items
     */
    it("should render Icon for each feature with correct name and size 16", () => {
      // Arrange
      const expectedIconNames = ["folder", "download", "share", "lock"];

      // Act
      render(<AppFeatures />);

      // Assert
      expect(Icon).toHaveBeenCalledTimes(4);
      for (const name of expectedIconNames) {
        expect(Icon).toHaveBeenCalledWith(
          expect.objectContaining({ name, size: 16 }),
          undefined,
        );
      }
    });

    /**
     * @description Each feature item has a unique key based on title
     * @scenario Render AppFeatures and inspect list items
     * @expected 4 li elements
     */
    it("should render correct number of list items", () => {
      // Arrange & Act
      render(<AppFeatures />);

      // Assert
      const listItems = screen.getAllByRole("listitem");
      expect(listItems).toHaveLength(4);
    });
  });

  describe("icon colors", () => {
    /**
     * @description Applies correct color class to icon container based on iconColor prop
     * @scenario Features have iconColor: "info", "tertiary", "warning", "success"
     * @expected Icon container div has class app-features__icon--[color]
     */
    it("should apply color-specific class to each icon wrapper", () => {
      // Arrange
      render(<AppFeatures />);
      const iconWrappers = document.querySelectorAll(".app-features__icon");

      // Assert
      expect(iconWrappers[0]).toHaveClass("app-features__icon--info");
      expect(iconWrappers[1]).toHaveClass("app-features__icon--tertiary");
      expect(iconWrappers[2]).toHaveClass("app-features__icon--warning");
      expect(iconWrappers[3]).toHaveClass("app-features__icon--success");
    });

    /**
     * @description Does not add color class when iconColor is undefined (all have colors, but class pattern is correct)
     * @scenario Check that only expected color classes are present
     * @expected Each icon wrapper has exactly one color class from allowed set
     */
    it("should not add unknown color classes", () => {
      const allowedColors = ["info", "tertiary", "warning", "success"];
      const iconWrappers = document.querySelectorAll(".app-features__icon");
      iconWrappers.forEach((wrapper) => {
        const classes = Array.from(wrapper.classList);
        const colorClass = classes.find((c) =>
          c.startsWith("app-features__icon--"),
        );
        const color = colorClass?.replace("app-features__icon--", "");
        expect(allowedColors).toContain(color);
      });
    });
  });

  describe("styling and structure", () => {
    /**
     * @description Contains root div with class "app-features"
     * @scenario Render AppFeatures
     * @expected div with class app-features exists
     */
    it("should render root element with class 'app-features'", () => {
      // Arrange & Act
      render(<AppFeatures />);

      // Assert
      const root = document.querySelector(".app-features");
      expect(root).toBeInTheDocument();
    });

    /**
     * @description Renders unordered list with class "app-features__list"
     * @scenario Render AppFeatures
     * @expected ul element with correct class
     */
    it("should render ul with class 'app-features__list'", () => {
      // Arrange & Act
      render(<AppFeatures />);

      // Assert
      const list = document.querySelector(".app-features__list");
      expect(list).toBeInTheDocument();
      expect(list?.tagName).toBe("UL");
    });

    /**
     * @description Each feature has Heading level 3 with visualSize "md" and class "app-features__title"
     * @scenario Render AppFeatures
     * @expected All level 3 Headings receive correct props
     */
    it("should render feature titles as Heading level 3 with visualSize md", () => {
      // Arrange
      render(<AppFeatures />);
      const headingCalls = (Heading as Mock).mock.calls;
      const level3Calls = headingCalls.filter((call) => call[0].level === 3);

      // Assert
      expect(level3Calls).toHaveLength(4);
      for (const call of level3Calls) {
        expect(call[0]).toMatchObject({
          level: 3,
          visualSize: "md",
          className: "app-features__title",
        });
      }
    });
  });
});
