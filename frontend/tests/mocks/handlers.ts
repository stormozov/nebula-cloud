import { HttpResponse, http } from "msw";

export const handlers = [
	// Mock для аутентификации
	http.post("/api/auth/login/", () => {
		return HttpResponse.json(
			{
				user: {
					id: 1,
					login: "testuser",
					email: "test@example.com",
					is_admin: false,
				},
			},
			{ status: 200 },
		);
	}),

	// Mock для получения списка файлов
	http.get("/api/files/", () => {
		return HttpResponse.json(
			{
				count: 0,
				next: null,
				previous: null,
				results: [],
			},
			{ status: 200 },
		);
	}),

	// Mock для загрузки файла
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
