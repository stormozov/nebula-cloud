import { HttpResponse, http } from "msw";

/**
 * File API handlers
 */
export const fileApiHandlers = [
  // GET /storage/files/ - Get file list
  http.get("/api/storage/files/", () => {
    return HttpResponse.json([
      {
        id: 1,
        originalName: "test.txt",
        comment: null,
        size: 1024,
        sizeFormatted: "1 KB",
        uploadedAt: new Date().toISOString(),
        lastDownloaded: null,
        hasPublicLink: false,
        publicLinkUrl: null,
        downloadUrl: "/api/storage/files/1/download/",
      },
    ]);
  }),

  // GET /storage/files/:id/ - Get file info
  http.get("/api/storage/files/:id/", ({ params }) => {
    const id = Number(params.id);
    if (id === 999) {
      return HttpResponse.json({ detail: "File not found" }, { status: 404 });
    }
    return HttpResponse.json({
      id,
      originalName: `file${id}.txt`,
      comment: null,
      size: 1024,
      sizeFormatted: "1 KB",
      uploadedAt: new Date().toISOString(),
      lastDownloaded: null,
      hasPublicLink: false,
      publicLinkUrl: null,
      downloadUrl: `/api/storage/files/${id}/download/`,
    });
  }),

  // DELETE /storage/files/:id/ - Delete file
  http.delete("/api/storage/files/:id/", ({ params }) => {
    const id = Number(params.id);
    if (id === 999) {
      return HttpResponse.json({ detail: "File not found" }, { status: 404 });
    }
    return HttpResponse.json(null, { status: 204 });
  }),

  // PATCH /storage/files/:id/rename/ - Rename file
  http.patch("/api/storage/files/:id/rename/", async ({ params, request }) => {
    const id = Number(params.id);
    const body = (await request.json()) as { originalName: string };
    if (id === 999) {
      return HttpResponse.json({ detail: "File not found" }, { status: 404 });
    }
    return HttpResponse.json({
      id,
      originalName: body.originalName,
      comment: null,
      size: 1024,
      sizeFormatted: "1 KB",
      uploadedAt: new Date().toISOString(),
      lastDownloaded: null,
      hasPublicLink: false,
      publicLinkUrl: null,
      downloadUrl: `/api/storage/files/${id}/download/`,
    });
  }),

  // PATCH /storage/files/:id/comment/ - Set comment
  http.patch("/api/storage/files/:id/comment/", async ({ params, request }) => {
    const id = Number(params.id);
    const body = (await request.json()) as { comment: string };
    if (id === 999) {
      return HttpResponse.json({ detail: "File not found" }, { status: 404 });
    }
    return HttpResponse.json({
      id,
      originalName: `file${id}.txt`,
      comment: body.comment,
      size: 1024,
      sizeFormatted: "1 KB",
      uploadedAt: new Date().toISOString(),
      lastDownloaded: null,
      hasPublicLink: false,
      publicLinkUrl: null,
      downloadUrl: `/api/storage/files/${id}/download/`,
    });
  }),

  // POST /storage/files/:id/public-link/generate/ - Generate public link
  http.post("/api/storage/files/:id/public-link/generate/", ({ params }) => {
    const id = Number(params.id);
    if (id === 999) {
      return HttpResponse.json({ detail: "File not found" }, { status: 404 });
    }
    return HttpResponse.json({
      id,
      originalName: `file${id}.txt`,
      comment: null,
      size: 1024,
      sizeFormatted: "1 KB",
      uploadedAt: new Date().toISOString(),
      lastDownloaded: null,
      hasPublicLink: true,
      publicLinkUrl: `https://example.com/public/${id}`,
      downloadUrl: `/api/storage/files/${id}/download/`,
    });
  }),

  // DELETE /storage/files/:id/public-link/ - Delete public link
  http.delete("/api/storage/files/:id/public-link/", ({ params }) => {
    const id = Number(params.id);
    if (id === 999) {
      return HttpResponse.json({ detail: "File not found" }, { status: 404 });
    }
    return HttpResponse.json({
      id,
      originalName: `file${id}.txt`,
      comment: null,
      size: 1024,
      sizeFormatted: "1 KB",
      uploadedAt: new Date().toISOString(),
      lastDownloaded: null,
      hasPublicLink: false,
      publicLinkUrl: null,
      downloadUrl: `/api/storage/files/${id}/download/`,
    });
  }),

  // POST /storage/files/ - Upload file
  http.post("/api/storage/files/", async ({ request }) => {
    const formData = await request.formData();
    const file = formData.get("file") as File;
    const comment = formData.get("comment") as string | null;

    if (!file || file.size === 0) {
      return HttpResponse.json({ detail: "No file provided" }, { status: 400 });
    }

    return HttpResponse.json(
      {
        id: 100,
        originalName: file.name,
        comment: comment || null,
        size: 1024,
        sizeFormatted: "1 KB",
        uploadedAt: new Date().toISOString(),
        lastDownloaded: null,
        hasPublicLink: false,
        publicLinkUrl: null,
        downloadUrl: "/api/storage/files/100/download/",
      },
      { status: 201 },
    );
  }),
];
