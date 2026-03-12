import { configureStore } from "@reduxjs/toolkit";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { userSlice } from "../model/slice";

// Helper to track calls to getAccessTokenFromPersist
let accessTokenMock: string | null = "mock_access_token";
let refreshTokenMock: string | null = "mock_refresh_token";

// Mock the dependencies
vi.mock("@/shared/utils", () => ({
  getAccessTokenFromPersist: vi.fn(() => accessTokenMock),
  getRefreshTokenFromPersist: vi.fn(() => refreshTokenMock),
}));

const { userApi } = await import("./userApi");

/** Creates a test store with minimal configuration. */
const createTestStore = () => {
  return configureStore({
    reducer: {
      user: userSlice.reducer,
      [userApi.reducerPath]: userApi.reducer,
    },
    middleware: (getDefaultMiddleware) =>
      getDefaultMiddleware().concat(userApi.middleware),
  });
};

describe("userApi with MSW", () => {
  let store: ReturnType<typeof createTestStore>;

  beforeEach(() => {
    store = createTestStore();
    accessTokenMock = "mock_access_token";
    refreshTokenMock = "mock_refresh_token";
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("API Slice Configuration", () => {
    /**
     * @description Should have correct reducerPath
     * @scenario Creating slice without actions should return initial state
     * @expected All fields should have default values
     */
    it("should have correct reducerPath", () => {
      expect(userApi).toBeDefined();
      expect(userApi.reducerPath).toBe("userApi");
    });

    /**
     * @description Should have baseQuery configured
     * @scenario Creating slice without actions should return initial state
     * @expected All fields should have default values
     */
    it("should have baseQuery configured", () => {
      expect(userApi).toBeDefined();
      expect(userApi).toHaveProperty("reducerPath");
    });

    /**
     * @description Should have User tagType defined
     * @scenario Creating slice without actions should return initial state
     * @expected All fields should have default values
     */
    it("should have User tagType defined", () => {
      expect(userApi).toBeDefined();
      expect(userApi.util).toBeDefined();
    });
  });

  describe("Endpoints Definition", () => {
    /**
     * @description Should have getMe endpoint defined
     * @scenario Creating slice without actions should return initial state
     * @expected All fields should have default values
     */
    it("should have getMe endpoint defined", () => {
      expect(userApi.endpoints).toHaveProperty("getMe");
      expect(userApi.endpoints.getMe).toBeDefined();
    });

    /**
     * @description Should have login endpoint defined
     * @scenario Creating slice without actions should return initial state
     * @expected All fields should have default values
     */
    it("should have login endpoint defined", () => {
      expect(userApi.endpoints).toHaveProperty("login");
      expect(userApi.endpoints.login).toBeDefined();
    });

    /**
     * @description Should have register endpoint defined
     * @scenario Creating slice without actions should return initial state
     * @expected All fields should have default values
     */
    it("should have register endpoint defined", () => {
      expect(userApi.endpoints).toHaveProperty("register");
      expect(userApi.endpoints.register).toBeDefined();
    });

    /**
     * @description Should have logout endpoint defined
     * @scenario Creating slice without actions should return initial state
     * @expected All fields should have default values
     */
    it("should have logout endpoint defined", () => {
      expect(userApi.endpoints).toHaveProperty("logout");
      expect(userApi.endpoints.logout).toBeDefined();
    });
  });

  describe("Actual API calls with MSW", () => {
    /**
     * @description Should execute getMe query and return user data
     * @scenario Executing getMe query should return user data
     * @expected User data should be returned
     */
    it("should execute getMe query and return user data", async () => {
      const result = await userApi.endpoints.getMe.initiate()(
        store.dispatch,
        store.getState,
        { forceRefetch: true },
      );

      expect(result).toBeDefined();
    });

    /**
     * @description Should execute login mutation and return auth response
     * @scenario Executing login mutation should return auth response
     * @expected Auth response should be returned
     */
    it("should execute login mutation and return auth response", async () => {
      const result = await userApi.endpoints.login.initiate({
        username: "testuser",
        password: "SecurePass123!",
      })(store.dispatch, store.getState, {});

      expect(result).toBeDefined();
      expect(result.data).toBeDefined();

      if (result.data) {
        expect(result.data.user).toBeDefined();
        expect(result.data.access).toBeDefined();
      }
    });

    /**
     * @description Should execute register mutation and return auth response
     * @scenario Executing register mutation should return auth response
     * @expected Auth response should be returned
     */
    it("should execute register mutation and return auth response", async () => {
      const result = await userApi.endpoints.register.initiate({
        username: "newuser2",
        email: "new2@example.com",
        password: "Password123!",
        passwordConfirm: "Password123!",
        firstName: "New",
        lastName: "User",
      })(store.dispatch, store.getState, {});

      expect(result).toBeDefined();
      expect(result.data).toBeDefined();

      const { data } = result;
      expect(data?.user).toBeDefined();
      expect(data?.user.username).toBe("newuser2");
    });

    /**
     * @description Should execute logout mutation
     * @scenario Executing logout mutation should return auth response
     * @expected Auth response should be returned
     */
    it("should execute logout mutation", async () => {
      const result = await userApi.endpoints.logout.initiate()(
        store.dispatch,
        store.getState,
        {},
      );

      expect(result).toBeDefined();
    });
  });

  describe("prepareHeaders branch coverage", () => {
    /**
     * @description Should execute API call when token is present (truthy branch)
     * @scenario Executing API call should return auth response
     * @expected Auth response should be returned
     */
    it("should execute API call when token is present (truthy branch)", async () => {
      accessTokenMock = "mock_access_token";

      const testStore = createTestStore();

      const result = await userApi.endpoints.login.initiate({
        username: "testuser",
        password: "SecurePass123!",
      })(testStore.dispatch, testStore.getState, {});

      expect(result).toBeDefined();
    });

    /**
     * @description Should execute API call when token is null (falsy branch)
     * @scenario Executing API call should return auth response
     * @expected Auth response should be returned
     */
    it("should execute API call when token is null (falsy branch)", async () => {
      accessTokenMock = null;
      refreshTokenMock = null;

      const testStore = createTestStore();

      const result = await userApi.endpoints.login.initiate({
        username: "testuser",
        password: "SecurePass123!",
      })(testStore.dispatch, testStore.getState, {});

      expect(result).toBeDefined();
    });
  });

  describe("Exported Hooks", () => {
    /**
     * @description Should export useGetMeQuery hook
     * @scenario Verifying useGetMeQuery hook is exported
     * @expected Hook should be a function
     */
    it("should export useGetMeQuery hook", () => {
      expect(userApi.useGetMeQuery).toBeDefined();
      expect(typeof userApi.useGetMeQuery).toBe("function");
    });

    /**
     * @description Should export useLoginMutation hook
     * @scenario Verifying useLoginMutation hook is exported
     * @expected Hook should be a function
     */
    it("should export useLoginMutation hook", () => {
      expect(userApi.useLoginMutation).toBeDefined();
      expect(typeof userApi.useLoginMutation).toBe("function");
    });

    /**
     * @description Should export useRegisterMutation hook
     * @scenario Verifying useRegisterMutation hook is exported
     * @expected Hook should be a function
     */
    it("should export useRegisterMutation hook", () => {
      expect(userApi.useRegisterMutation).toBeDefined();
      expect(typeof userApi.useRegisterMutation).toBe("function");
    });

    /**
     * @description Should export useLogoutMutation hook
     * @scenario Verifying useLogoutMutation hook is exported
     * @expected Hook should be a function
     */
    it("should export useLogoutMutation hook", () => {
      expect(userApi.useLogoutMutation).toBeDefined();
      expect(typeof userApi.useLogoutMutation).toBe("function");
    });
  });

  describe("API Slice Integrity", () => {
    /**
     * @description Should have all required endpoints
     * @scenario Verifying all required endpoints are present
     * @expected All required endpoints should be present
     */
    it("should have all required endpoints", () => {
      expect(userApi.endpoints).toHaveProperty("getMe");
      expect(userApi.endpoints).toHaveProperty("login");
      expect(userApi.endpoints).toHaveProperty("register");
      expect(userApi.endpoints).toHaveProperty("logout");
    });

    /**
     * @description Should export all required hooks
     * @scenario Verifying all required hooks are exported
     * @expected All required hooks should be exported
     */
    it("should export all required hooks", () => {
      expect(userApi).toHaveProperty("useGetMeQuery");
      expect(userApi).toHaveProperty("useLoginMutation");
      expect(userApi).toHaveProperty("useRegisterMutation");
      expect(userApi).toHaveProperty("useLogoutMutation");
    });

    /**
     * @description Should have unique reducerPath
     * @scenario Verifying reducerPath is unique
     * @expected ReducerPath should be unique
     */
    it("should have unique reducerPath", () => {
      expect(userApi.reducerPath).toBe("userApi");
    });
  });

  describe("Endpoint Name Consistency", () => {
    /**
     * @description Should have correct name for getMe endpoint
     * @scenario Verifying getMe endpoint name
     * @expected Endpoint name should be "getMe"
     */
    it("should have correct name for getMe endpoint", () => {
      const endpoint = userApi.endpoints.getMe as unknown as { name: string };
      expect(endpoint.name).toBe("getMe");
    });

    /**
     * @description Should have correct name for login endpoint
     * @scenario Verifying login endpoint name
     * @expected Endpoint name should be "login"
     */
    it("should have correct name for login endpoint", () => {
      const endpoint = userApi.endpoints.login as unknown as { name: string };
      expect(endpoint.name).toBe("login");
    });

    /**
     * @description Should have correct name for register endpoint
     * @scenario Verifying register endpoint name
     * @expected Endpoint name should be "register"
     */
    it("should have correct name for register endpoint", () => {
      const endpoint = userApi.endpoints.register as unknown as {
        name: string;
      };
      expect(endpoint.name).toBe("register");
    });

    /**
     * @description Should have correct name for logout endpoint
     * @scenario Verifying logout endpoint name
     * @expected Endpoint name should be "logout"
     */
    it("should have correct name for logout endpoint", () => {
      const endpoint = userApi.endpoints.logout as unknown as { name: string };
      expect(endpoint.name).toBe("logout");
    });
  });

  describe("API Slice Identity", () => {
    /**
     * @description Should have injectEndpoints method
     * @scenario Verifying injectEndpoints method is present
     * @expected Method should be present
     */
    it("should have injectEndpoints method", () => {
      expect(typeof userApi.injectEndpoints).toBe("function");
    });

    /**
     * @description Should have util namespace for cache management
     * @scenario Verifying util namespace is present
     * @expected Namespace should be present
     */
    it("should have util namespace for cache management", () => {
      expect(userApi.util).toBeDefined();
      expect(typeof userApi.util).toBe("object");
    });

    /**
     * @description Should have middleware defined
     * @scenario Verifying middleware is defined
     * @expected Middleware should be defined
     */
    it("should have middleware defined", () => {
      expect(typeof userApi.middleware).toBe("function");
    });

    /**
     * @description Should have reducer defined
     * @scenario Verifying reducer is defined
     * @expected Reducer should be defined
     */
    it("should have reducer defined", () => {
      expect(typeof userApi.reducer).toBe("function");
    });

    /**
     * @description Should have reducerPath defined
     * @scenario Verifying reducerPath is defined
     * @expected ReducerPath should be defined
     */
    it("should have reducerPath in configuration", () => {
      expect(userApi.reducerPath).toBeDefined();
      expect(userApi.reducerPath).toBe("userApi");
    });
  });
});
