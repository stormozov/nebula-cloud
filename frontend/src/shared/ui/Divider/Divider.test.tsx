import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Divider } from "./Divider";

describe("Divider", () => {
  describe("when rendered with default props", () => {
    /**
     * @description Should render an <hr> element with divider class and zero vertical margins
     * @scenario Render Divider without gap prop
     * @expected Element has role 'separator', class 'divider', and marginTop/marginBottom set to 0
     */
    it("should render hr with divider class and zero margins when gap is not provided", () => {
      // Arrange
      render(<Divider />);

      // Act
      const hr = screen.getByRole("separator");

      // Assert
      expect(hr).toBeInTheDocument();
      expect(hr).toHaveClass("divider");
      expect(hr.style.marginTop).toBe("0px");
      expect(hr.style.marginBottom).toBe("0px");
    });
  });

  describe("when gap prop is a number", () => {
    /**
     * @description Should apply the numeric gap value to both marginTop and marginBottom
     * @scenario Render Divider with gap={20}
     * @expected marginTop and marginBottom equal '20px'
     */
    it("should set marginTop and marginBottom to px value when gap is number", () => {
      // Arrange
      render(<Divider gap={20} />);

      // Act
      const hr = screen.getByRole("separator");

      // Assert
      expect(hr.style.marginTop).toBe("20px");
      expect(hr.style.marginBottom).toBe("20px");
    });
  });

  describe("when gap prop is a string", () => {
    /**
     * @description Should apply the string gap value directly to marginTop and marginBottom
     * @scenario Render Divider with gap="1.5rem"
     * @expected marginTop and marginBottom equal '1.5rem'
     */
    it("should set marginTop and marginBottom to string value when gap is string", () => {
      // Arrange
      render(<Divider gap="1.5rem" />);

      // Act
      const hr = screen.getByRole("separator");

      // Assert
      expect(hr.style.marginTop).toBe("1.5rem");
      expect(hr.style.marginBottom).toBe("1.5rem");
    });
  });

  describe("when gap prop is zero explicitly", () => {
    /**
     * @description Should set zero margins when gap={0} is explicitly passed
     * @scenario Render Divider with gap={0}
     * @expected marginTop and marginBottom equal '0px'
     */
    it("should set zero margins when gap is explicitly 0", () => {
      // Arrange
      render(<Divider gap={0} />);

      // Act
      const hr = screen.getByRole("separator");

      // Assert
      expect(hr.style.marginTop).toBe("0px");
      expect(hr.style.marginBottom).toBe("0px");
    });
  });
});
