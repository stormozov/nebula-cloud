// No ReactEvent needed

/**
 * Mock form event for testing form submission handlers.
 * Provides preventDefault for e.preventDefault() calls.
 */
export interface IMockFormEvent {
  preventDefault: () => void;
}
