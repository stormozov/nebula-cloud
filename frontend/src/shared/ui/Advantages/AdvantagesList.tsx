import classNames from "classnames";

import type { SemanticColor } from "@/shared/types/common";

import { Heading } from "../Heading";
import { Icon, type IconName } from "../Icon";

import "./AdvantagesList.scss";

/**
 * Interface defining the structure of a single advantage item.
 */
interface IAdvantageItem {
  /**The name of the icon to display for this advantage. */
  icon: IconName;
  /** The title or headline of the advantage. */
  title: string;
  /** Detailed description of the advantage. */
  description: string;
  /**
   * Optional semantic color for the icon.
   *
   * @remarks
   * If provided, applies a color class to the icon container to reflect
   * the tone of the advantage (e.g., "success", "warning").
   */
  iconColor?: SemanticColor;
}

/**
 * Type alias for an array of advantage items.
 */
type Advantages = IAdvantageItem[];

/**
 * Readonly array of predefined advantage items displayed in the app.
 */
const ADVANTAGES: Advantages = [
  {
    icon: "upload",
    title: "Быстрая загрузка",
    description: "Загружайте файлы любых форматов одним кликом",
    iconColor: "info",
  },
  {
    icon: "lock",
    title: "Безопасность",
    description: "Ваши файлы защищены и доступны только вам",
    iconColor: "success",
  },
  {
    icon: "share",
    title: "Общий доступ",
    description: "Делитесь файлами через специальные ссылки",
    iconColor: "warning",
  },
] as const;

/**
 * A React component that renders a list of application advantages.
 */
export function AdvantagesList() {
  return (
    <ul className="advantages-list">
      {ADVANTAGES.map((advantage) => (
        <div key={advantage.title} className="advantages-list__item">
          <div
            className={classNames("advantages-list__icon", {
              [`advantages-list__icon--${advantage.iconColor}`]:
                advantage.iconColor,
            })}
          >
            <Icon name={advantage.icon} size={24} />
          </div>

          <Heading level={3} className="advantages-list__title" noMargin>
            {advantage.title}
          </Heading>

          <p className="advantages-list__description">
            {advantage.description}
          </p>
        </div>
      ))}
    </ul>
  );
}
