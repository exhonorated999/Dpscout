// iOS Device and Backup Types

export interface IosDevice {
  udid: string;
  deviceName: string;
  deviceModel: string;
  productType: string;
  iosVersion: string;
  serialNumber: string;
  phoneNumber?: string;
  imei?: string;
  lastBackupDate: string;
  backupPath: string;
}

export interface IosApp {
  bundleId: string;
  appName: string;
  version: string;
  bundleVersion: string;
  isSystemApp: boolean;
}

export interface IosMessage {
  messageId: number;
  chatId: number;
  sender: string;
  messageText: string;
  date: string;
  isFromMe: boolean;
  service: string; // "SMS" or "iMessage"
}

export interface IosContact {
  recordId: number;
  firstName: string;
  lastName: string;
  phoneNumbers: string[];
  emails: string[];
}

export interface IosCall {
  callId: number;
  phoneNumber: string;
  date: string;
  duration: number;
  callType: string; // "Incoming", "Outgoing", "Missed"
}

export interface IosBrowserHistory {
  url: string;
  title: string;
  visitCount: number;
  lastVisit: string;
}

export interface IosMedia {
  filename: string;
  filePath: string;
  creationDate: string;
  modificationDate: string;
  fileSize: number;
  latitude?: number;
  longitude?: number;
}

export interface IosWhatsAppMessage {
  messageId: number;
  chatId: string;
  sender: string;
  messageText: string;
  timestamp: string;
  isFromMe: boolean;
}

export interface IosBackupData {
  device: IosDevice;
  apps: IosApp[];
  messages: IosMessage[];
  contacts: IosContact[];
  calls: IosCall[];
  browserHistory: IosBrowserHistory[];
  mediaFiles: IosMedia[];
}

// iOS triage categories
export const IOS_DATA_CATEGORIES = {
  DEVICE_INFO: 'Device Info',
  APPLICATIONS: 'Applications',
  MESSAGES: 'Messages & iMessage',
  CONTACTS: 'Contacts',
  CALLS: 'Call History',
  BROWSER: 'Safari History',
  PHOTOS: 'Photos & Videos',
  WHATSAPP: 'WhatsApp',
  TELEGRAM: 'Telegram',
  SNAPCHAT: 'Snapchat',
  INSTAGRAM: 'Instagram',
} as const;

// Critical artifact hashes for forensic investigation
export const IOS_ARTIFACT_HASHES: Record<string, string> = {
  'SMS Database': '3d0d7e5fb2ce288813306e4d4636395e047a3d28',
  'AddressBook': '31bb7ba8914766d4ba40d6dfb6113c8b614be442',
  'Call History': '2b2b0084a1bc3a5ac8c27afdf14afb42c61a19ca',
  'Safari History': '5e0da3ef69e20fd3d22c2cd37a7d73e38d78a3c1',
  'Safari Bookmarks': '0dfe50a0a1a8e5e5ba2e1b5e8b8f6e7b8e5e5ba2',
  'Calendar': '2041457d5fe04d39d0ab481178355df6781e6858',
  'Notes': 'ca3bc056d4da0bbf88b5fb3be254f3b7147e639c',
  'Photos Database': '12b144c0bd44f2b3dffd9186d3f9c05b917cee25',
  'WhatsApp Messages': '7c7fba66680ef796b916b067077cc246adacf01d',
  'Telegram Cache': '2dfc1b53b655d67c33e1b33d9c36f8ad99dc1c0c',
};

// Common social media app bundle IDs
export const IOS_SOCIAL_MEDIA_APPS = {
  WHATSAPP: 'net.whatsapp.WhatsApp',
  TELEGRAM: 'ph.telegra.Telegraph',
  SIGNAL: 'org.whispersystems.signal',
  SNAPCHAT: 'com.toyopagroup.picaboo',
  INSTAGRAM: 'com.burbn.instagram',
  FACEBOOK: 'com.facebook.Facebook',
  MESSENGER: 'com.facebook.Messenger',
  TIKTOK: 'com.zhiliaoapp.musically',
  TWITTER: 'com.atebits.Tweetie2',
  DISCORD: 'com.hammerandchisel.discord',
  KIK: 'com.kik.chat',
  WICKR: 'com.wickr.enterprise',
  THREEMA: 'ch.threema.iapp',
  VIBER: 'com.viber',
  LINE: 'jp.naver.line',
  WECHAT: 'com.tencent.xin',
  KAKAOTALK: 'com.kakao.talk',
} as const;
