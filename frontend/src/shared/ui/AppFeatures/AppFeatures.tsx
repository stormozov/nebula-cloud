import classNames from "classnames";

import type { SemanticColor } from "@/shared/types/common";

import { Heading, type IHeadingProps } from "../Heading";
import { Icon, type IconName } from "../Icon";

import "./AppFeatures.scss";

/**
 * Interface defining the structure of a single application feature item.
 */
interface IAppFeaturesItem {
  /** The name of the icon to display for this feature. */
  icon: IconName;
  /** The title or headline of the feature. */
  title: string;
  /** Detailed description of the feature. */
  description: string;
  /**
   * Optional semantic color for the icon.
   *
   * @remarks
   * If provided, applies a color class to the icon container to reflect
   * the tone of the feature (e.g., "success", "warning").
   */
  iconColor?: SemanticColor;
}

/**
 * Type alias for an array of application feature items.
 */
type AppFeaturesList = IAppFeaturesItem[];

/**
 * Static list of application features displayed in the app.
 */
const appFeaturesList: AppFeaturesList = [
  {
    icon: "folder",
    title: "Управление файлами",
    description:
      "Загружайте, переименовывайте, удаляйте файлы и добавляйте комментарии",
    iconColor: "info",
  },
  {
    icon: "download",
    title: "Скачивание файлов",
    description: "Просматривайте и скачивайте свои файлы в любое время",
    iconColor: "tertiary",
  },
  {
    icon: "share",
    title: "Специальные ссылки",
    description: "Генерируйте уникальные ссылки для доступа к файлам",
    iconColor: "warning",
  },
  {
    icon: "lock",
    title: "Безопасность",
    description: "Ваши файлы защищены и доступны только вам",
    iconColor: "success",
  },
];

/**
 * Props interface for the {@link AppFeatures} component.
 */
interface IAppFeaturesProps {
  /** Optional props to pass to the heading component. */
  titleProps?: IHeadingProps;
}

/**
 * A React component that displays a list of key application features.
 */
export function AppFeatures({ titleProps }: IAppFeaturesProps) {
  return (
    <div className="app-features">
      {titleProps?.children && <Heading level={2} {...titleProps} />}
      <ul className="app-features__list">
        {appFeaturesList.map((feature) => (
          <li key={feature.title} className="app-features__item">
            <div
              className={classNames("app-features__icon", {
                [`app-features__icon--${feature.iconColor}`]: feature.iconColor,
              })}
            >
              <Icon name={feature.icon} size={16} />
            </div>
            <div className="app-features__content">
              <Heading
                level={3}
                visualSize="md"
                className="app-features__title"
              >
                {feature.title}
              </Heading>
              <p className="app-features__description">{feature.description}</p>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
