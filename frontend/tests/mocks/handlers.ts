import { HttpResponse, http } from "msw";

/**
 * Mock handlers for authentication endpoints.
 */
export const handlers = [
  // ---------------------------------------------------------------------------
  // AUTHENTICATION
  // ---------------------------------------------------------------------------

  // Login endpoint
  http.post("/api/auth/login/", async ({ request }) => {
    const body = (await request.json()) as {
      username: string;
      password: string;
    };

    // Valid credentials
    if (body.username === "testuser" && body.password === "SecurePass123!") {
      return HttpResponse.json({
        access: "mock_access_token_12345",
        refresh: "mock_refresh_token_67890",
        user: {
          id: 1,
          username: "testuser",
          email: "test@example.com",
          first_name: "Test",
          last_name: "User",
          is_staff: false,
        },
      });
    }

    // Invalid credentials
    return HttpResponse.json(
      { detail: "Неверный логин или пароль." },
      { status: 400 },
    );
  }),

  // Register endpoint
  http.post("/api/auth/register/", async ({ request }) => {
    const body = (await request.json()) as {
      username: string;
      email: string;
      password: string;
      password_confirm: string;
      first_name: string;
      last_name: string;
    };

    // Check password confirmation
    if (body.password !== body.password_confirm) {
      return HttpResponse.json(
        { password_confirm: ["Пароли не совпадают."] },
        { status: 400 },
      );
    }

    // Check for existing username
    if (body.username === "existinguser") {
      return HttpResponse.json(
        { username: ["Пользователь с таким логином уже существует."] },
        { status: 400 },
      );
    }

    // Check for existing email
    if (body.email === "existing@example.com") {
      return HttpResponse.json(
        { email: ["Пользователь с таким email уже существует."] },
        { status: 400 },
      );
    }

    // Successful registration
    return HttpResponse.json(
      {
        access: "mock_access_token_new_user",
        refresh: "mock_refresh_token_new_user",
        user: {
          id: 2,
          username: body.username,
          email: body.email,
          first_name: body.first_name,
          last_name: body.last_name,
          is_staff: false,
        },
      },
      { status: 201 },
    );
  }),

  // Logout endpoint
  http.post("/api/auth/logout/", async ({ request }) => {
    const body = (await request.json()) as { refresh?: string };

    // Check for refresh token
    if (!body?.refresh) {
      return HttpResponse.json(
        { detail: "Refresh token is required." },
        { status: 400 },
      );
    }

    // Successful logout
    return HttpResponse.json(
      { detail: "Successfully logged out." },
      { status: 200 },
    );
  }),

  // Get current user endpoint
  http.get("/api/auth/me/", ({ request }) => {
    const authHeader = request.headers.get("Authorization");

    // Check for valid token
    if (authHeader === "Bearer mock_access_token_12345") {
      return HttpResponse.json({
        id: 1,
        username: "testuser",
        email: "test@example.com",
        first_name: "Test",
        last_name: "User",
        is_staff: false,
      });
    }

    // Invalid or missing token
    return HttpResponse.json(
      { detail: "Учетные данные не предоставлены." },
      { status: 401 },
    );
  }),

  // ---------------------------------------------------------------------------
  // FILES
  // ---------------------------------------------------------------------------

  // Get files list endpoint
  http.get("/api/files/", () => {
    return HttpResponse.json({
      count: 0,
      next: null,
      previous: null,
      results: [],
    });
  }),

  // Upload file endpoint
  http.post("/api/files/upload/", async ({ request }) => {
    const formData = await request.formData();
    const file = formData.get("file") as File;

    if (!file) {
      return HttpResponse.json({ error: "No file provided" }, { status: 400 });
    }

    return HttpResponse.json(
      {
        id: crypto.randomUUID(),
        original_name: file.name,
        size: file.size,
        uploaded_at: new Date().toISOString(),
        comment: (formData.get("comment") as string) || "",
      },
      { status: 201 },
    );
  }),
];
