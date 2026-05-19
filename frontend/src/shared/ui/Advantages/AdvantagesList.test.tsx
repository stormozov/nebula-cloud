import { render, screen } from "@testing-library/react";
import type { Mock } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { Heading } from "../Heading";
import { Icon } from "../Icon";
import { AdvantagesList } from "./AdvantagesList";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("../Heading", () => ({
  Heading: vi.fn(({ children, level, visualSize, noMargin, className }) => (
    <div
      data-testid="heading"
      data-level={level}
      data-visual-size={visualSize}
      data-no-margin={noMargin}
      className={className}
    >
      {children}
    </div>
  )),
}));

vi.mock("../Icon", () => ({
  Icon: vi.fn(({ name, size }) => (
    <div data-testid="icon" data-icon-name={name} data-size={size} />
  )),
}));

// =============================================================================
// TESTS
// =============================================================================

describe("AdvantagesList", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should render all three advantages with correct titles and descriptions", () => {
    const expectedTitles = ["Быстрая загрузка", "Безопасность", "Общий доступ"];
    const expectedDescriptions = [
      "Загружайте файлы любых форматов одним кликом",
      "Ваши файлы защищены и доступны только вам",
      "Делитесь файлами через специальные ссылки",
    ];

    render(<AdvantagesList />);

    expectedTitles.forEach((title) => {
      expect(screen.getByText(title)).toBeInTheDocument();
    });

    expectedDescriptions.forEach((description) => {
      expect(screen.getByText(description)).toBeInTheDocument();
    });
  });

  it("should render Heading component with correct props for each advantage", () => {
    const MockHeading = Heading as unknown as Mock;

    const expectedTitles = ["Быстрая загрузка", "Безопасность", "Общий доступ"];

    render(<AdvantagesList />);

    expect(MockHeading).toHaveBeenCalledTimes(3);

    expectedTitles.forEach((title, index) => {
      const callArgs = MockHeading.mock.calls[index];
      expect(callArgs[0]).toEqual(
        expect.objectContaining({
          level: 3,
          visualSize: "md",
          noMargin: true,
          className: "advantages-list__title",
          children: title,
        }),
      );
    });
  });

  it("should render Icon component with correct name and size for each advantage", () => {
    const MockIcon = Icon as unknown as Mock;

    const expectedIconNames = ["upload", "lock", "share"];

    render(<AdvantagesList />);

    expect(MockIcon).toHaveBeenCalledTimes(3);

    expectedIconNames.forEach((name, index) => {
      const callArgs = MockIcon.mock.calls[index];
      expect(callArgs[0]).toEqual(
        expect.objectContaining({
          name,
          size: 24,
        }),
      );
    });
  });

  it("should apply correct semantic color class to icon container for each advantage", () => {
    const expectedColorClasses = [
      "advantages-list__icon--info",
      "advantages-list__icon--success",
      "advantages-list__icon--warning",
    ];

    render(<AdvantagesList />);

    const iconContainers = document.querySelectorAll(".advantages-list__icon");
    expect(iconContainers).toHaveLength(3);

    iconContainers.forEach((container, index) => {
      expect(container).toHaveClass(expectedColorClasses[index]);
    });
  });

  it('should render a ul element with class "advantages-list"', () => {
    render(<AdvantagesList />);

    const list = document.querySelector("ul.advantages-list");
    expect(list).toBeInTheDocument();
  });

  it('should render three items with class "advantages-list__item"', () => {
    render(<AdvantagesList />);

    const items = document.querySelectorAll(".advantages-list__item");
    expect(items).toHaveLength(3);
  });
});
