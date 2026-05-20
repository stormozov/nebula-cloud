import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, type Mock, vi } from "vitest";

import { getInitials } from "@/shared/utils";

import { Avatar } from "./Avatar";

vi.mock("@/shared/utils", () => ({
  getInitials: vi.fn(),
}));

describe("Avatar", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (getInitials as Mock).mockReturnValue("JD");
  });

  describe("when src is provided and image loads successfully", () => {
    /**
     * @description Renders an img element with correct src, alt, and classes
     * @scenario Avatar rendered with valid src and alt="John Doe"
     * @expected img element appears, no fallback div, classes include avatar and avatar--md
     */
    it("should render img with correct src, alt, and size class", () => {
      // Arrange
      const src = "https://example.com/avatar.jpg";
      const alt = "John Doe";

      // Act
      render(<Avatar src={src} alt={alt} />);

      // Assert
      const img = screen.getByRole("img", { name: alt });
      expect(img).toBeInTheDocument();
      expect(img).toHaveAttribute("src", src);
      expect(img).toHaveClass("avatar", "avatar--md");
      expect(img).not.toHaveClass("avatar--fallback");
    });

    /**
     * @description Applies custom className to img element
     * @scenario Avatar rendered with className="custom-class"
     * @expected img includes custom-class along with default classes
     */
    it("should merge custom className with default classes", () => {
      // Arrange
      render(<Avatar src="test.jpg" alt="Jane" className="custom-class" />);

      // Act
      const img = screen.getByRole("img");

      // Assert
      expect(img).toHaveClass("avatar", "avatar--md", "custom-class");
    });
  });

  describe("when src is not provided", () => {
    /**
     * @description Renders fallback div with initials and no img
     * @scenario Avatar rendered without src prop, alt="Alice Smith"
     * @expected Div with class avatar--fallback and text content "AS"
     */
    it("should render fallback div with initials", () => {
      // Arrange
      const alt = "Alice Smith";
      (getInitials as Mock).mockReturnValue("AS");

      // Act
      render(<Avatar alt={alt} />);

      // Assert
      const fallback = screen.getByText("AS");
      expect(fallback).toBeInTheDocument();
      expect(fallback.tagName).toBe("DIV");
      expect(fallback).toHaveClass("avatar", "avatar--md", "avatar--fallback");
      expect(screen.queryByRole("img")).not.toBeInTheDocument();
      expect(getInitials).toHaveBeenCalledWith(alt);
    });
  });

  describe("when image fails to load", () => {
    /**
     * @description Switches to fallback after onError triggered on img
     * @scenario Avatar with src triggers error event on img
     * @expected img disappears, fallback div with initials appears, getInitials called with alt
     */
    it("should fall back to initials when image onError fires", () => {
      // Arrange
      render(<Avatar src="broken.jpg" alt="Broken User" />);
      const img = screen.getByRole("img");

      // Act
      fireEvent.error(img);

      // Assert
      expect(screen.queryByRole("img")).not.toBeInTheDocument();
      const fallback = screen.getByText("JD");
      expect(fallback).toBeInTheDocument();
      expect(fallback).toHaveClass("avatar--fallback");
      expect(getInitials).toHaveBeenCalledWith("Broken User");
    });

    /**
     * @description Does not call fallback again after error already occurred (state persists)
     * @scenario Image errors once, then re-renders but still shows fallback
     * @expected Fallback remains, no img
     */
    it("should not attempt to reload image after error", () => {
      // Arrange
      render(<Avatar src="broken.jpg" alt="Test" />);
      const img = screen.getByRole("img");

      // Act
      fireEvent.error(img);

      // Assert
      expect(screen.queryByRole("img")).not.toBeInTheDocument();
      expect(screen.getByText("JD")).toBeInTheDocument();
    });
  });

  describe("size variations", () => {
    /**
     * @description Applies correct size class for small size
     * @scenario Avatar with size="sm"
     * @expected Element (img or fallback) has class avatar--sm
     */
    it('should add avatar--sm class when size="sm"', () => {
      // Arrange & Act
      render(<Avatar alt="User" size="sm" />);

      // Assert
      const element = screen.getByText("JD");
      expect(element).toHaveClass("avatar--sm");
    });

    /**
     * @description Applies correct size class for large size
     * @scenario Avatar with size="lg"
     * @expected Element has class avatar--lg
     */
    it('should add avatar--lg class when size="lg"', () => {
      // Arrange & Act
      render(<Avatar alt="User" size="lg" />);

      // Assert
      const element = screen.getByText("JD");
      expect(element).toHaveClass("avatar--lg");
    });

    /**
     * @description Uses default md size when size prop omitted
     * @scenario Avatar without size prop
     * @expected Element has avatar--md class
     */
    it("should default to avatar--md when size not provided", () => {
      // Arrange & Act
      render(<Avatar alt="User" />);

      // Assert
      const element = screen.getByText("JD");
      expect(element).toHaveClass("avatar--md");
    });
  });

  describe("accessibility", () => {
    /**
     * @description Uses alt text as aria-label for img
     * @scenario Avatar rendered with src and alt="Profile picture"
     * @expected img has alt attribute equal to "Profile picture"
     */
    it("should set correct alt attribute on img", () => {
      // Arrange
      const alt = "Profile picture";
      render(<Avatar src="valid.jpg" alt={alt} />);

      // Act
      const img = screen.getByRole("img");

      // Assert
      expect(img).toHaveAttribute("alt", alt);
    });

    /**
     * @description Fallback div includes initials as text, no alt needed
     * @scenario Avatar without src, alt="John Wick"
     * @expected Div contains "JW" and is accessible as text
     */
    it("should display initials from alt text for fallback", () => {
      // Arrange
      (getInitials as Mock).mockReturnValue("JW");
      render(<Avatar alt="John Wick" />);

      // Act & Assert
      expect(screen.getByText("JW")).toBeInTheDocument();
    });
  });
});
