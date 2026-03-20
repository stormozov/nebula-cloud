import { useState } from "react";
import { FaDownload } from "react-icons/fa6";
import { useNavigate, useParams } from "react-router";

import {
  useDownloadPublicFileMutation,
  useGetPublicFileQuery,
} from "@/entities/file";
import { Button, FileIcon, PageLayout } from "@/shared/ui";
import {
  downloadFile as downloadFileUtils,
  formatDate,
  formatFileSize,
} from "@/shared/utils";

import "./PagePublicFile.scss";

/**
 * Page for public file access via token.
 *
 * Displays file metadata and download button.
 */
export default function PagePublicFile() {
  const { token } = useParams<{ token: string }>();
  const navigate = useNavigate();

  const {
    data: file,
    isLoading,
    error,
  } = useGetPublicFileQuery(token || "", { skip: !token });

  const [downloadFile, { isLoading: isDownloading }] =
    useDownloadPublicFileMutation();
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const handleDownload = async (): Promise<void> => {
    if (!file || !token) return;

    setDownloadError(null);

    try {
      const result = await downloadFile({
        token,
        filename: file.originalName,
      }).unwrap();

      const blob: Blob = result;
      downloadFileUtils(blob, file.originalName);
    } catch (err) {
      console.error("Download failed:", err);
      setDownloadError("Не удалось скачать файл");
    }
  };

  if (isLoading) {
    // Loading state
    return (
      <div className="page-public-file page-public-file--loading">
        <div className="page-public-file__loader">Загрузка...</div>
      </div>
    );
  }

  if (error || !file) {
    // Error state
    return (
      <div className="page-public-file page-public-file--error">
        <div className="page-public-file__error">
          <h2>Ошибка</h2>
          <p>
            {error
              ? "Файл не найден или ссылка недействительна"
              : "Файл не найден"}
          </p>
          <Button variant="primary" onClick={() => navigate("/")}>
            На главную
          </Button>
        </div>
      </div>
    );
  }

  return (
    <PageLayout className="page-public-file">
      <div className="page-public-file__card">
        <div className="page-public-file__icon">
          <FileIcon filename={file.originalName} size={80} />
        </div>

        <div className="page-public-file__info">
          <h1 className="page-public-file__name" title={file.originalName}>
            {file.originalName}
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
              <dd>{formatDate(file.uploadedAt)}</dd>
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
            <FaDownload />
            {isDownloading ? "Скачивание..." : "Скачать файл"}
          </Button>
        </div>

        {downloadError && (
          <div className="page-public-file__download-error">
            <p className="page-public-file__download-error-text">
              {downloadError}
            </p>
          </div>
        )}

        <p className="page-public-file__hint">
          Файл будет скачан с оригинальным именем:
          <br />
          <strong>{file.originalName}</strong>
        </p>
      </div>
    </PageLayout>
  );
}
