import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router";

import { API_BASE_URL } from "@/shared/api";
import { Button, FileIcon } from "@/shared/ui";
import { formatDate, formatFileSize } from "@/shared/utils";

import "./PagePublicFile.scss";

/**
 * Page for public file access via token.
 *
 * Displays file metadata and download button.
 */
export default function PagePublicFile() {
  const { token } = useParams<{ token: string }>();
  const navigate = useNavigate();

  const [file, setFile] = useState<{
    original_name: string;
    size: number;
    size_formatted: string;
    uploaded_at: string;
    comment: string;
    download_url: string;
  } | null>(null);

  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isDownloading, setIsDownloading] = useState(false);

  /**
   * Fetch file metadata from public API.
   */
  useEffect(() => {
    if (!token) {
      setError("Неверная ссылка");
      setIsLoading(false);
      return;
    }

    const fetchFileMetadata = async () => {
      try {
        const response = await fetch(
          `${API_BASE_URL}/storage/public/${token}/`,
        );

        if (!response.ok) {
          if (response.status === 404) {
            throw new Error("Файл не найден или ссылка недействительна");
          }
          throw new Error(`Ошибка сервера: ${response.status}`);
        }

        const data = await response.json();
        setFile(data);
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Не удалось загрузить информацию о файле",
        );
      } finally {
        setIsLoading(false);
      }
    };

    fetchFileMetadata();
  }, [token]);

  /**
   * Trigger file download.
   */
  const handleDownload = async (): Promise<void> => {
    if (!file?.download_url) return;

    setIsDownloading(true);

    try {
      // 🔧 Загружаем файл как blob
      const response = await fetch(file.download_url);

      if (!response.ok) {
        throw new Error("Не удалось скачать файл");
      }

      // 🔧 Получаем blob и создаём ссылку для скачивания
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = file.original_name; // 🔧 Оригинальное имя файла
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Download failed:", err);
      setError("Не удалось скачать файл");
    } finally {
      setIsDownloading(false);
    }
  };

  // Loading state
  if (isLoading) {
    return (
      <div className="page-public-file page-public-file--loading">
        <div className="page-public-file__loader">Загрузка...</div>
      </div>
    );
  }

  // Error state
  if (error || !file) {
    return (
      <div className="page-public-file page-public-file--error">
        <div className="page-public-file__error">
          <h2>Ошибка</h2>
          <p>{error || "Файл не найден"}</p>
          <Button variant="primary" onClick={() => navigate("/")}>
            На главную
          </Button>
        </div>
      </div>
    );
  }

  // Success state
  return (
    <div className="page-public-file">
      <div className="page-public-file__card">
        <div className="page-public-file__icon">
          <FileIcon filename={file.original_name} size={64} />
        </div>

        <div className="page-public-file__info">
          <h1 className="page-public-file__name" title={file.original_name}>
            {file.original_name}
          </h1>

          {file.comment && (
            <p className="page-public-file__comment">{file.comment}</p>
          )}

          <dl className="page-public-file__meta">
            <div>
              <dt>Размер:</dt>
              <dd>{formatFileSize(file.size)}</dd>
            </div>
            <div>
              <dt>Загружен:</dt>
              <dd>{formatDate(file.uploaded_at)}</dd>
            </div>
          </dl>
        </div>

        <div className="page-public-file__actions">
          <Button
            variant="primary"
            size="large"
            onClick={handleDownload}
            loading={isDownloading}
            fullWidth
          >
            {isDownloading ? "Скачивание..." : "Скачать файл"}
          </Button>
        </div>

        <p className="page-public-file__hint">
          Файл будет скачан с оригинальным именем:
          <br />
          <strong>{file.original_name}</strong>
        </p>
      </div>
    </div>
  );
}
