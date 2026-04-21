import { AiOutlineClose } from "react-icons/ai";
import { BiSolidDashboard } from "react-icons/bi";
import {
  BsFillLightbulbFill,
  BsInfoSquareFill,
  BsLightbulbOffFill,
} from "react-icons/bs";
import {
  FaEye,
  FaFolder,
  FaLock,
  FaSave,
  FaUpload,
  FaUserPlus,
  FaUserTimes,
} from "react-icons/fa";
import {
  FaCheck,
  FaComment,
  FaCopy,
  FaDownload,
  FaFileExport,
  FaLinkSlash,
  FaPencil,
  FaQuestion,
  FaShareNodes,
  FaTrashCan,
  FaUser,
} from "react-icons/fa6";
import { FiMoreVertical } from "react-icons/fi";
import { IoIosArrowBack, IoIosArrowForward, IoIosCloud } from "react-icons/io";
import { IoReloadSharp, IoSearch } from "react-icons/io5";
import {
  MdEdit,
  MdLogin,
  MdLogout,
  MdOutlineDoNotDisturbAlt,
} from "react-icons/md";
import { PiPasswordBold, PiWarningDiamondFill } from "react-icons/pi";
import { RiAdminFill } from "react-icons/ri";
import { TbError404 } from "react-icons/tb";
import { MdSunny } from "react-icons/md";
import { IoMoon } from "react-icons/io5";
import { PiMonitorFill } from "react-icons/pi";

import CloudBadIcon from "@/assets/images/icons/CloudBadIcon.svg?react";
import CloudLoadingIcon from "@/assets/images/icons/CloudLoadingIcon.svg?react";
import CloudWarningIcon from "@/assets/images/icons/CloudWarningIcon.svg?react";

import { createIconAdapter } from "./iconAdapter";

/**
 * A constant object that maps icon names to their corresponding React component
 * icons.
 *
 * This object provides a centralized registry of icons used throughout
 * the application, grouped by categories for better organization
 * and maintainability.
 *
 * @example
 * import { ICONS } from './icons';
 * const EditIcon = ICONS.edit;
 */
export const ICONS = {
  // ========== Actions ==========
  edit: MdEdit,
  save: FaSave,
  retry: IoReloadSharp,
  copy: FaCopy,
  share: FaShareNodes,
  upload: FaUpload,
  download: FaDownload,
  trash: FaTrashCan,
  pencil: FaPencil,
  export: FaFileExport,
  search: IoSearch,
  more: FiMoreVertical,

  // ========== Navigation & UI ==========
  close: AiOutlineClose,
  eye: FaEye,
  comment: FaComment,
  dashboard: BiSolidDashboard,

  // ========== Status & Feedback ==========
  check: FaCheck,
  warning: PiWarningDiamondFill,
  infoSquare: BsInfoSquareFill,
  doNotDisturb: MdOutlineDoNotDisturbAlt,
  cloudBad: createIconAdapter(CloudBadIcon),
  cloudWarning: createIconAdapter(CloudWarningIcon),
  cloudLoading: createIconAdapter(CloudLoadingIcon),
  notFound: TbError404,
  question: FaQuestion,

  // ========== User & Admin ==========
  person: FaUser,
  adminStatus: RiAdminFill,
  deleteUser: FaUserTimes,
  lock: FaLock,
  password: PiPasswordBold,
  login: MdLogin,
  register: FaUserPlus,
  logout: MdLogout,

  // ========== Files & Folders ==========
  folder: FaFolder,
  cloud: IoIosCloud,
  deleteLink: FaLinkSlash,

  // ========== Arrows ==========
  arrowRight: IoIosArrowForward,
  arrowLeft: IoIosArrowBack,

  // ========== Theme / Mode ==========
  lightbulbOn: BsFillLightbulbFill,
  lightbulbOff: BsLightbulbOffFill,
  sun: MdSunny,
  moon: IoMoon,
  monitor: PiMonitorFill,
} as const;
