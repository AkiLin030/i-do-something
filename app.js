
// ============================================
// 安全認證與真實驗證加密工具 (Web Crypto API)
// ============================================
async function hashPassword(password, salt) {
  try {
    if (window.crypto && window.crypto.subtle) {
      const enc = new TextEncoder();
      const data = enc.encode(password + '::life_salt::' + salt);
      const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
  } catch (e) {
    console.warn('Crypto subtle fallback:', e);
  }
  let hash = 0;
  const str = password + salt;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return 'h_' + Math.abs(hash).toString(16);
}

function generateSecureSalt() {
  if (window.crypto && window.crypto.getRandomValues) {
    const arr = new Uint8Array(16);
    window.crypto.getRandomValues(arr);
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

function generate6DigitCode() {
  if (window.crypto && window.crypto.getRandomValues) {
    const arr = new Uint32Array(1);
    window.crypto.getRandomValues(arr);
    return String(100000 + (arr[0] % 900000));
  }
  return String(Math.floor(100000 + Math.random() * 900000));
}

function parseJwt(token) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function (c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
  } catch (e) {
    console.error('Failed to parse JWT:', e);
    return null;
  }
}

// 四大生活類型定義
const TYPE_CONFIG = {
  housework: { name: '家事生活', shortName: '家事', color: '#10B981' },
  outing: { name: '出去玩/休閒', shortName: '休閒', color: '#F87171' },
  work: { name: '工作/學習', shortName: '工作', color: '#F8FAFC' },
  health: { name: '健康自律', shortName: '健康', color: '#FBBF24' }
};

// 統一風格的 24x24 向量線條圖標庫 (Feather / Lucide 極簡風格)
const ICON_SVGS = {
  // 家事生活
  laundry: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="3"/><circle cx="12" cy="13" r="5"/><path d="M12 10a3 3 0 0 0-3 3"/><circle cx="7" cy="6" r="1"/></svg>`,
  hang: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="6" r="2"/><path d="M12 8v3l-8 5v2h16v-2l-8-5"/></svg>`,
  dishes: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.5"/></svg>`,
  trash: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>`,
  clean: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l2.4 5 5.6.8-4 4 1 5.6-5-2.6-5 2.6 1-5.6-4-4 5.6-.8z"/></svg>`,

  // 出去玩/休閒
  walk: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="4" r="2"/><path d="M10 22l3-7-2-4 3-2 3 4"/><path d="M8 12l2-3 3 1"/></svg>`,
  movie: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="6" width="20" height="12" rx="3"/><line x1="6" y1="12" x2="10" y2="12"/><line x1="8" y1="10" x2="8" y2="14"/><circle cx="15" cy="11" r="1"/><circle cx="17" cy="13" r="1"/></svg>`,
  dine: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8h1a4 4 0 0 1 0 8h-1"/><path d="M2 8h16v9a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8z"/><line x1="6" y1="2" x2="6" y2="4"/><line x1="10" y1="2" x2="10" y2="4"/><line x1="14" y1="2" x2="14" y2="4"/></svg>`,
  rest: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`,

  // 工作/學習
  work: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M2 20h20"/><path d="M9 16v4m6-4v4"/></svg>`,
  study: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>`,

  // 健康自律
  early: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="13" r="8"/><polyline points="12 9 12 13 15 14"/><path d="M5 3L2 6m20 0l-3-3"/></svg>`,
  exercise: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 5v14M18 5v14M2 9v6M22 9v6M6 12h12"/></svg>`,
  water: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.69l5.66 5.66a8 8 0 1 1-11.31 0z"/></svg>`,

  // 通用擴充向量圖標
  temp: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
  perm: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>`,
  heart: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>`,
  star: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`,
  car: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="11" width="20" height="8" rx="2"/><circle cx="7" cy="18" r="2"/><circle cx="17" cy="18" r="2"/><path d="M5 11l2-6h10l2 6"/></svg>`,
  cart: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="21" r="1"/><circle cx="20" cy="21" r="1"/><path d="M1 1h4l2.68 13.39a2 2 0 0 0 2 1.61h9.72a2 2 0 0 0 2-1.61L23 6H6"/></svg>`,
  bulb: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18h6m-4 4h2m-5-8.5a7 7 0 1 1 8 0c-.8.8-1.5 2-1.5 3.5H10.5c0-1.5-.7-2.7-1.5-3.5z"/></svg>`,
  tool: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>`,
  music: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>`,
  coffee: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8h1a4 4 0 0 1 0 8h-1"/><path d="M2 8h16v9a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8z"/><line x1="6" y1="2" x2="6" y2="4"/><line x1="10" y1="2" x2="10" y2="4"/><line x1="14" y1="2" x2="14" y2="4"/></svg>`,
  sun: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32l1.41 1.41M2 12h2m16 0h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>`,
  pen: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19l7-7 3 3-7 7-3-3z"/><path d="M18 13l-1.5-7.5L2 2l3.5 14.5L13 18l5-5z"/><circle cx="11" cy="11" r="2"/></svg>`,
  smile: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>`
};

// 取得統一風格向量圖標 (相容舊版表情符號或新版 ID)
function getIconSvg(iconKeyOrEmoji, type = 'housework') {
  const emojiMap = {
    '🧺': 'laundry', '☀️': 'hang', '🧼': 'dishes', '🗑️': 'trash', '✨': 'clean',
    '🚶': 'walk', '🍿': 'movie', '🍲': 'dine', '☕': 'rest', '💻': 'work',
    '📚': 'study', '⏰': 'early', '🏃': 'exercise', '💧': 'water', '🧹': 'clean',
    '🌿': 'clean', '🐱': 'rest', '🎮': 'movie', '🚗': 'car', '🛒': 'cart',
    '💡': 'bulb', '🛠️': 'tool', '🍜': 'dine', '🎨': 'study', '⚡': 'temp', '＋': 'perm'
  };
  const key = emojiMap[iconKeyOrEmoji] || iconKeyOrEmoji;
  if (ICON_SVGS[key]) return ICON_SVGS[key];
  if (type === 'outing') return ICON_SVGS.movie;
  if (type === 'work') return ICON_SVGS.work;
  if (type === 'health') return ICON_SVGS.early;
  return ICON_SVGS.clean;
}

// 預設常駐生活項目庫 (使用統一線條圖標鍵名)
const DEFAULT_PRESETS = [
  // 家事生活 (綠色)
  { id: 'p_laundry', name: '洗衣服', icon: 'laundry', type: 'housework', tags: ['丟洗衣機', '手洗', '洗床單', '摺衣服'] },
  { id: 'p_hang', name: '曬衣服', icon: 'hang', type: 'housework', tags: ['曬衣服', '收衣服', '曬被子'] },
  { id: 'p_dishes', name: '洗碗', icon: 'dishes', type: 'housework', tags: ['手洗乾淨', '洗大鍋', '水槽放光'] },
  { id: 'p_trash', name: '倒垃圾', icon: 'trash', type: 'housework', tags: ['追垃圾車', '回收', '廚餘清潔'] },
  { id: 'p_clean', name: '整理房間', icon: 'clean', type: 'housework', tags: ['吸地拖地', '換床單', '斷捨離'] },

  // 出去玩/休閒 (紅色)
  { id: 'p_walk', name: '出門散步', icon: 'walk', type: 'outing', tags: ['公園放空', '曬曬太陽', '深呼吸'] },
  { id: 'p_movie', name: '休閒娛樂', icon: 'movie', type: 'outing', tags: ['看好電影', '打電動', '追劇放鬆'] },
  { id: 'p_dine', name: '吃頓好料', icon: 'dine', type: 'outing', tags: ['朋友聚餐', '吃大餐', '喝下午茶'] },
  { id: 'p_rest', name: '放空充能', icon: 'rest', type: 'outing', tags: ['好好睡覺', '聽音樂', '泡熱水澡'] },

  // 工作/學習 (白色)
  { id: 'p_work', name: '專注工作', icon: 'work', type: 'work', tags: ['搞定專案', '清空待辦', '寫代碼', '開會'] },
  { id: 'p_study', name: '閱讀學習', icon: 'study', type: 'work', tags: ['看書30分', '線上課程', '寫筆記'] },

  // 健康自律 (黃色)
  { id: 'p_early', name: '努力早起', icon: 'early', type: 'health', tags: ['沒賴床', '吃早餐', '8點前起床'] },
  { id: 'p_exercise', name: '運動健身', icon: 'exercise', type: 'health', tags: ['跑步30分', '健身重訓', '瑜珈拉筋'] },
  { id: 'p_water', name: '喝足夠水', icon: 'water', type: 'health', tags: ['早起溫水', '1000cc', '2000cc達標'] }
];

// 自訂彈窗可選圖標列表
const AVAILABLE_ICONS = ['laundry', 'hang', 'dishes', 'trash', 'clean', 'walk', 'movie', 'dine', 'rest', 'work', 'study', 'early', 'exercise', 'water', 'heart', 'star', 'car', 'cart', 'bulb', 'tool', 'music', 'coffee', 'sun', 'smile'];

// 成就系統 (移除所有「解鎖條件:」贅字)
const ACHIEVEMENTS = [
  { id: 'first_step', name: '踏出第一步', desc: '記錄第一筆生活努力，生活開始有了形狀！', requirement: '記錄第 1 筆生活足跡', icon: '🌱', unlocked: true, condition: acts => acts.length >= 1 },
  {
    id: 'heat_full', name: '今日大滿貫', desc: '單日記錄做了 8 件以上的事，格子完全填滿！', requirement: '單日努力累積達 8 件事（月曆填滿）', icon: '🔥', unlocked: false, condition: acts => {
      const counts = {};
      acts.forEach(a => { counts[a.date] = (counts[a.date] || 0) + 1; });
      return Object.values(counts).some(c => c >= 8);
    }
  },
  { id: 'dishes_5', name: '碗盤清道夫', desc: '累計洗碗 5 次，水槽天天亮晶晶！', requirement: '累計完成洗碗 5 次', icon: '🧼', unlocked: false, condition: acts => acts.filter(a => a.name === '洗碗').length >= 5 },
  { id: 'outing_fun', name: '生活有張有弛', desc: '記錄了出門散步或休閒娛樂，該玩就玩！', requirement: '記錄 1 筆休閒或出去玩項目', icon: '🍿', unlocked: false, condition: acts => acts.some(a => a.type === 'outing') },
  { id: 'days_7', name: '生活軌跡一週連線', desc: '本月累積有努力記錄的天數達到 7 天', requirement: '單月累積努力天數達 7 天', icon: '🗓️', unlocked: false, condition: acts => new Set(acts.map(a => a.date)).size >= 7 },
  { id: 'work_focus', name: '心流專注大師', desc: '專注工作或閱讀學習累積達 5 次', requirement: '完成工作或學習達 5 次', icon: '💻', unlocked: false, condition: acts => acts.filter(a => a.type === 'work').length >= 5 },
  { id: 'clean_streak', name: '家事達人勳章', desc: '家事生活類項目累計達到 10 次', requirement: '累積完成家事類努力 10 次', icon: '🧹', unlocked: false, condition: acts => acts.filter(a => a.type === 'housework').length >= 10 },
  {
    id: 'night_owl', name: '夜行性家事狂', desc: '在深夜 23:00 ~ 04:00 記錄做完的事', requirement: '於深夜時段記錄生活足跡', icon: '🦉', unlocked: false, condition: acts => acts.some(a => {
      if (!a.time) return false;
      const h = parseInt(a.time.split(':')[0], 10);
      return h >= 23 || h < 4;
    })
  }
];

// 初始示範資料
function generateInitialRecords() {
  const today = new Date();
  const y = today.getFullYear();
  const m = String(today.getMonth() + 1).padStart(2, '0');
  const fmt = (day) => `${y}-${m}-${String(day).padStart(2, '0')}`;

  return [
    // 今天 (多件家事，主要為綠色)
    { id: 'act-1', date: fmt(today.getDate()), time: '09:00', name: '努力早起', icon: 'early', type: 'health', note: '8點前起床沒賴床' },
    { id: 'act-2', date: fmt(today.getDate()), time: '10:30', name: '洗衣服', icon: 'laundry', type: 'housework', note: '洗床單＋丟洗衣機' },
    { id: 'act-3', date: fmt(today.getDate()), time: '11:15', name: '曬衣服', icon: 'hang', type: 'housework', note: '曬衣服＋曬被子' },
    { id: 'act-4', date: fmt(today.getDate()), time: '13:00', name: '洗碗', icon: 'dishes', type: 'housework', note: '手洗乾淨' },
    { id: 'act-5', date: fmt(today.getDate()), time: '15:30', name: '出門散步', icon: 'walk', type: 'outing', note: '公園曬曬太陽' },

    // 昨天 (休閒，紅色)
    { id: 'act-6', date: fmt(Math.max(1, today.getDate() - 1)), time: '12:00', name: '吃頓好料', icon: 'dine', type: 'outing', note: '美味義大利麵' },
    { id: 'act-7', date: fmt(Math.max(1, today.getDate() - 1)), time: '15:00', name: '休閒娛樂', icon: 'movie', type: 'outing', note: '看了一部好看的電影' },
    { id: 'act-8', date: fmt(Math.max(1, today.getDate() - 1)), time: '19:00', name: '放空充能', icon: 'rest', type: 'outing', note: '聽音樂放鬆' },

    // 前天 (工作，白色)
    { id: 'act-9', date: fmt(Math.max(1, today.getDate() - 2)), time: '10:00', name: '專注工作', icon: 'work', type: 'work', note: '搞定核心架構代碼' },
    { id: 'act-10', date: fmt(Math.max(1, today.getDate() - 2)), time: '14:30', name: '閱讀學習', icon: 'study', type: 'work', note: '看了30分鐘新技術書籍' },

    // 8件大滿貫示範
    { id: 'act-11', date: fmt(Math.max(1, today.getDate() - 4)), time: '08:00', name: '努力早起', icon: 'early', type: 'health', note: '早起' },
    { id: 'act-12', date: fmt(Math.max(1, today.getDate() - 4)), time: '09:00', name: '洗衣服', icon: 'laundry', type: 'housework', note: '洗衣服' },
    { id: 'act-13', date: fmt(Math.max(1, today.getDate() - 4)), time: '10:00', name: '曬衣服', icon: 'hang', type: 'housework', note: '曬被子' },
    { id: 'act-14', date: fmt(Math.max(1, today.getDate() - 4)), time: '11:00', name: '整理房間', icon: 'clean', type: 'housework', note: '吸地拖地' },
    { id: 'act-15', date: fmt(Math.max(1, today.getDate() - 4)), time: '12:30', name: '洗碗', icon: 'dishes', type: 'housework', note: '洗碗' },
    { id: 'act-16', date: fmt(Math.max(1, today.getDate() - 4)), time: '15:00', name: '倒垃圾', icon: 'trash', type: 'housework', note: '倒垃圾' },
    { id: 'act-17', date: fmt(Math.max(1, today.getDate() - 4)), time: '17:00', name: '運動健身', icon: 'exercise', type: 'health', note: '跑步' },
    { id: 'act-18', date: fmt(Math.max(1, today.getDate() - 4)), time: '21:00', name: '喝足夠水', icon: 'water', type: 'health', note: '2000cc達標' }
  ];
}

class LifeAchievementApp {
  constructor() {
    this.usersKey = 'life_users_v1';
    this.currentUserKey = 'life_current_user_v1';
    this.guestStorageKey = 'life_records_v6';
    this.guestAchieveKey = 'life_achieve_v6';

    this.currentUser = this.loadCurrentUser();
    this.storageKey = this.currentUser ? `life_records_${this.currentUser.id}` : this.guestStorageKey;
    this.achieveKey = this.currentUser ? `life_achieve_${this.currentUser.id}` : this.guestAchieveKey;
    this.presetsKey = 'life_presets_v6';
    this.tagHistoryKey = 'life_tag_history_v6';

    this.presets = this.loadPresets();
    this.records = this.loadRecords();
    this.achievements = this.loadAchievements();
    this.tagHistory = this.loadTagHistory(); // 記憶寫過的細節標籤

    const now = new Date();
    this.viewYear = now.getFullYear();
    this.viewMonth = now.getMonth();
    this.selectedDate = null;

    // 當前畫面 ('footprint' | 'gallery')
    this.currentScreen = 'footprint';

    // 快速記錄彈窗狀態
    this.modalTargetDate = new Date();
    this.selectedPreset = this.presets[0];

    // 共用自訂彈窗狀態
    this.customType = 'housework';
    this.customIcon = '✨';

    // 正在編輯的紀錄 ID
    this.editingRecordId = null;
    this.editingRecordType = 'housework';

    // 帳號認證與 Google 官方認證狀態
    this.authMode = 'login'; // 'login' | 'register'
    this.googleClientIdKey = 'life_google_client_id';
    this.googleClientId = localStorage.getItem(this.googleClientIdKey) || '194967263380-lgnf5e2pshtb8a029qnkf39i9doqbqfq.apps.googleusercontent.com';
    this.pendingRegistration = null;

    this.initElements();
    this.bindEvents();
    this.renderAll();
    this.initGoogleIdentity();
  }

  loadCurrentUser() {
    const raw = localStorage.getItem(this.currentUserKey);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch { return null; }
  }

  saveCurrentUser(user) {
    if (!user) {
      localStorage.removeItem(this.currentUserKey);
    } else {
      localStorage.setItem(this.currentUserKey, JSON.stringify(user));
    }
  }

  loadUsers() {
    const raw = localStorage.getItem(this.usersKey);
    if (!raw) return [];
    try { return JSON.parse(raw); } catch { return []; }
  }

  saveUsers(users) {
    localStorage.setItem(this.usersKey, JSON.stringify(users));
  }

  loadPresets() {
    const raw = localStorage.getItem(this.presetsKey);
    if (!raw) return [...DEFAULT_PRESETS];
    try { return JSON.parse(raw); } catch { return [...DEFAULT_PRESETS]; }
  }

  savePresets() {
    localStorage.setItem(this.presetsKey, JSON.stringify(this.presets));
  }

  loadRecords() {
    const raw = localStorage.getItem(this.storageKey);
    if (!raw) {
      // 若已登入且專屬庫尚無資料，嘗試從訪客庫繼承努力足跡
      if (this.currentUser) {
        const guestRaw = localStorage.getItem(this.guestStorageKey);
        if (guestRaw) {
          try {
            const guestRecs = JSON.parse(guestRaw);
            if (guestRecs && guestRecs.length > 0) {
              localStorage.setItem(this.storageKey, JSON.stringify(guestRecs));
              return guestRecs;
            }
          } catch (e) { }
        }
      }
      const inits = generateInitialRecords();
      localStorage.setItem(this.storageKey, JSON.stringify(inits));
      return inits;
    }
    try { return JSON.parse(raw); } catch { return generateInitialRecords(); }
  }

  saveRecords() {
    localStorage.setItem(this.storageKey, JSON.stringify(this.records));
  }

  loadAchievements() {
    const raw = localStorage.getItem(this.achieveKey);
    if (!raw) {
      if (this.currentUser) {
        const guestRaw = localStorage.getItem(this.guestAchieveKey);
        if (guestRaw) {
          try {
            const saved = JSON.parse(guestRaw);
            return ACHIEVEMENTS.map(a => ({
              ...a,
              unlocked: saved[a.id] !== undefined ? saved[a.id] : a.unlocked
            }));
          } catch (e) { }
        }
      }
      return ACHIEVEMENTS;
    }
    try {
      const saved = JSON.parse(raw);
      return ACHIEVEMENTS.map(a => ({
        ...a,
        unlocked: saved[a.id] !== undefined ? saved[a.id] : a.unlocked
      }));
    } catch { return ACHIEVEMENTS; }
  }

  saveAchievements() {
    const state = {};
    this.achievements.forEach(a => { state[a.id] = a.unlocked; });
    localStorage.setItem(this.achieveKey, JSON.stringify(state));
  }

  loadTagHistory() {
    const raw = localStorage.getItem(this.tagHistoryKey);
    if (!raw) return {};
    try { return JSON.parse(raw); } catch { return {}; }
  }

  saveTagHistory() {
    localStorage.setItem(this.tagHistoryKey, JSON.stringify(this.tagHistory));
  }

  initElements() {
    this.screenFootprint = document.getElementById('screen-footprint');
    this.screenAchievementsGallery = document.getElementById('screen-achievements-gallery');

    this.dockBtnFootprint = document.getElementById('dockBtnFootprint');
    this.dockBtnGallery = document.getElementById('dockBtnGallery');
    this.btnOpenEntry = document.getElementById('btnOpenEntry');

    this.currentMonthTitle = document.getElementById('currentMonthTitle');
    this.btnPrevMonth = document.getElementById('btnPrevMonth');
    this.btnNextMonth = document.getElementById('btnNextMonth');
    this.btnQuickAchievements = document.getElementById('btnQuickAchievements');

    this.calendarGrid = document.getElementById('calendarGrid');
    this.recordsContainer = document.getElementById('recordsContainer');
    this.recordsScrollContainer = document.getElementById('recordsScrollContainer');

    // 快速記錄視窗
    this.modalEntry = document.getElementById('modal-entry');
    this.btnCloseEntry = document.getElementById('btnCloseEntry');
    this.modalDateDisplay = document.getElementById('modalDateDisplay');
    this.btnModalPrevDay = document.getElementById('btnModalPrevDay');
    this.btnModalNextDay = document.getElementById('btnModalNextDay');
    this.presetsGrid = document.getElementById('presetsGrid');
    this.modalTagsRow = document.getElementById('modalTagsRow');
    this.inputCustomNote = document.getElementById('inputCustomNote');
    this.btnConfirmRecord = document.getElementById('btnConfirmRecord');

    // 共用自訂項目彈窗 (暫時與常駐共用同一組件)
    this.modalUnifiedCustom = document.getElementById('modal-unified-custom');
    this.unifiedCustomTitle = document.getElementById('unifiedCustomTitle');
    this.btnCloseUnifiedCustom = document.getElementById('btnCloseUnifiedCustom');
    this.inputCustomName = document.getElementById('inputCustomName');
    this.customTypePicker = document.getElementById('customTypePicker');
    this.customIconPickerGrid = document.getElementById('customIconPickerGrid');
    this.chkSaveToPresets = document.getElementById('chkSaveToPresets');
    this.toggleSubhint = document.getElementById('toggleSubhint');
    this.inputCustomDetailNote = document.getElementById('inputCustomDetailNote');
    this.btnSubmitUnifiedCustom = document.getElementById('btnSubmitUnifiedCustom');
    this.btnSubmitCustomText = document.getElementById('btnSubmitCustomText');

    // 編輯紀錄彈窗
    this.modalEditRecord = document.getElementById('modal-edit-record');
    this.btnCloseEditModal = document.getElementById('btnCloseEditModal');
    this.inputEditName = document.getElementById('inputEditName');
    this.inputEditNote = document.getElementById('inputEditNote');
    this.editTypePicker = document.getElementById('editTypePicker');
    this.btnSaveEditRecord = document.getElementById('btnSaveEditRecord');

    // 成就展覽室
    this.trophyRoomGrid = document.getElementById('trophyRoomGrid');
    this.galleryProgressBadge = document.getElementById('galleryProgressBadge');
    this.galleryProgressPct = document.getElementById('galleryProgressPct');
    this.galleryProgressBar = document.getElementById('galleryProgressBar');

    // 帳號與同步相關元素
    this.btnUserAccount = document.getElementById('btnUserAccount');
    this.headerAvatarCircle = document.getElementById('headerAvatarCircle');
    this.headerUserStatusDot = document.getElementById('headerUserStatusDot');
    this.btnUserAccountGallery = document.getElementById('btnUserAccountGallery');
    this.headerAvatarCircleGallery = document.getElementById('headerAvatarCircleGallery');
    this.headerUserStatusDotGallery = document.getElementById('headerUserStatusDotGallery');

    // 帳號登入 / 註冊彈窗
    this.modalAuth = document.getElementById('modal-auth');
    this.btnCloseAuthModal = document.getElementById('btnCloseAuthModal');
    this.googleRealBtnContainer = document.getElementById('googleRealBtnContainer');
    this.btnGoogleLogin = document.getElementById('btnGoogleLogin');

    this.btnTabLogin = document.getElementById('btnTabLogin');
    this.btnTabRegister = document.getElementById('btnTabRegister');
    this.authAlertBox = document.getElementById('authAlertBox');
    this.formAuth = document.getElementById('formAuth');
    this.groupRegisterName = document.getElementById('groupRegisterName');
    this.inputAuthName = document.getElementById('inputAuthName');
    this.inputAuthEmail = document.getElementById('inputAuthEmail');
    this.inputAuthPassword = document.getElementById('inputAuthPassword');
    this.btnTogglePassword = document.getElementById('btnTogglePassword');
    this.pwdStrengthBar = document.getElementById('pwdStrengthBar');
    this.strengthMeter = document.getElementById('strengthMeter');
    this.strengthLabel = document.getElementById('strengthLabel');
    this.groupRegisterConfirmPwd = document.getElementById('groupRegisterConfirmPwd');
    this.inputAuthConfirmPassword = document.getElementById('inputAuthConfirmPassword');
    this.btnSubmitAuth = document.getElementById('btnSubmitAuth');
    this.txtSubmitAuth = document.getElementById('txtSubmitAuth');
    this.btnGuestContinue = document.getElementById('btnGuestContinue');

    // 個人帳號與同步中心彈窗
    this.modalUserProfile = document.getElementById('modal-user-profile');
    this.btnCloseProfileModal = document.getElementById('btnCloseProfileModal');
    this.profileLargeAvatar = document.getElementById('profileLargeAvatar');
    this.profileDisplayName = document.getElementById('profileDisplayName');
    this.profileProviderTag = document.getElementById('profileProviderTag');
    this.profileEmailText = document.getElementById('profileEmailText');
    this.profileStatRecords = document.getElementById('profileStatRecords');
    this.profileStatDays = document.getElementById('profileStatDays');
    this.profileStatBadges = document.getElementById('profileStatBadges');
    this.btnSwitchAccount = document.getElementById('btnSwitchAccount');
    this.btnLogoutAccount = document.getElementById('btnLogoutAccount');
  }

  bindEvents() {
    this.dockBtnFootprint.addEventListener('click', () => this.switchScreen('footprint'));
    this.dockBtnGallery.addEventListener('click', () => this.switchScreen('gallery'));
    this.btnQuickAchievements.addEventListener('click', () => this.showQuickAchievementsModal());

    this.btnPrevMonth.addEventListener('click', () => {
      this.viewMonth -= 1;
      if (this.viewMonth < 0) {
        this.viewMonth = 11;
        this.viewYear -= 1;
      }
      this.selectedDate = null;
      this.renderAll();
      if (this.recordsScrollContainer) this.recordsScrollContainer.scrollTo({ top: 0, behavior: 'smooth' });
    });

    this.btnNextMonth.addEventListener('click', () => {
      this.viewMonth += 1;
      if (this.viewMonth > 11) {
        this.viewMonth = 0;
        this.viewYear += 1;
      }
      this.selectedDate = null;
      this.renderAll();
      if (this.recordsScrollContainer) this.recordsScrollContainer.scrollTo({ top: 0, behavior: 'smooth' });
    });

    this.btnOpenEntry.addEventListener('click', () => this.openEntryModal());
    this.btnCloseEntry.addEventListener('click', () => this.closeEntryModal());
    this.modalEntry.addEventListener('click', (e) => {
      if (e.target === this.modalEntry) this.closeEntryModal();
    });

    this.btnModalPrevDay.addEventListener('click', () => {
      this.modalTargetDate.setDate(this.modalTargetDate.getDate() - 1);
      this.updateModalDateDisplay();
    });
    this.btnModalNextDay.addEventListener('click', () => {
      this.modalTargetDate.setDate(this.modalTargetDate.getDate() + 1);
      this.updateModalDateDisplay();
    });

    this.btnConfirmRecord.addEventListener('click', () => this.onSavePresetRecord());

    // 共用自訂彈窗事件
    this.btnCloseUnifiedCustom.addEventListener('click', () => this.closeUnifiedCustomModal());
    this.modalUnifiedCustom.addEventListener('click', (e) => {
      if (e.target === this.modalUnifiedCustom) this.closeUnifiedCustomModal();
    });

    this.customTypePicker.querySelectorAll('.type-pick-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        this.customTypePicker.querySelectorAll('.type-pick-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.customType = btn.dataset.type;
        this.renderIconPicker();
      });
    });

    this.chkSaveToPresets.addEventListener('change', () => {
      this.updateCustomModalUI();
    });

    this.btnSubmitUnifiedCustom.addEventListener('click', () => this.onSubmitUnifiedCustom());

    // 編輯紀錄彈窗事件
    this.btnCloseEditModal.addEventListener('click', () => this.closeEditModal());
    this.modalEditRecord.addEventListener('click', (e) => {
      if (e.target === this.modalEditRecord) this.closeEditModal();
    });

    this.editTypePicker.querySelectorAll('.type-pick-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        this.editTypePicker.querySelectorAll('.type-pick-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.editingRecordType = btn.dataset.type;
      });
    });

    this.btnSaveEditRecord.addEventListener('click', () => this.onSaveEditedRecord());

    // 帳號按鈕點擊：未登入跳登入，已登入跳個人同步中心
    const handleAccountClick = () => {
      if (this.currentUser) {
        this.openUserProfileModal();
      } else {
        this.openAuthModal('login');
      }
    };
    if (this.btnUserAccount) this.btnUserAccount.addEventListener('click', handleAccountClick);
    if (this.btnUserAccountGallery) this.btnUserAccountGallery.addEventListener('click', handleAccountClick);

    // Auth 彈窗事件
    if (this.btnCloseAuthModal) this.btnCloseAuthModal.addEventListener('click', () => this.closeAuthModal());
    if (this.modalAuth) {
      this.modalAuth.addEventListener('click', (e) => {
        if (e.target === this.modalAuth) this.closeAuthModal();
      });
    }

    // Google 官方登入
    if (this.btnGoogleLogin) {
      this.btnGoogleLogin.addEventListener('click', () => {
        this.triggerGoogleLoginAction();
      });
    }

    if (this.btnTabLogin) this.btnTabLogin.addEventListener('click', () => this.switchAuthMode('login'));
    if (this.btnTabRegister) this.btnTabRegister.addEventListener('click', () => this.switchAuthMode('register'));

    if (this.btnTogglePassword) {
      this.btnTogglePassword.addEventListener('click', () => {
        const isPwd = this.inputAuthPassword.type === 'password';
        this.inputAuthPassword.type = isPwd ? 'text' : 'password';
      });
    }

    // 即時密碼強度偵測
    if (this.inputAuthPassword) {
      this.inputAuthPassword.addEventListener('input', () => {
        if (this.authMode === 'register') {
          this.updatePasswordStrengthUI(this.inputAuthPassword.value);
        }
      });
    }

    if (this.formAuth) {
      this.formAuth.addEventListener('submit', (e) => {
        e.preventDefault();
        this.submitEmailAuth();
      });
    }
    if (this.btnSubmitAuth) {
      this.btnSubmitAuth.addEventListener('click', (e) => {
        e.preventDefault();
        this.submitEmailAuth();
      });
    }

    if (this.btnGuestContinue) {
      this.btnGuestContinue.addEventListener('click', () => this.closeAuthModal());
    }

    // 個人中心彈窗事件
    if (this.btnCloseProfileModal) this.btnCloseProfileModal.addEventListener('click', () => this.closeUserProfileModal());
    if (this.modalUserProfile) {
      this.modalUserProfile.addEventListener('click', (e) => {
        if (e.target === this.modalUserProfile) this.closeUserProfileModal();
      });
    }

    if (this.btnSwitchAccount) {
      this.btnSwitchAccount.addEventListener('click', () => {
        this.closeUserProfileModal();
        this.openAuthModal('login');
      });
    }

    if (this.btnLogoutAccount) {
      this.btnLogoutAccount.addEventListener('click', () => {
        if (confirm('確定要登出目前帳號嗎？')) {
          this.logoutUser();
        }
      });
    }
  }

  switchScreen(screenName) {
    this.currentScreen = screenName;
    if (screenName === 'footprint') {
      this.screenFootprint.classList.add('active');
      this.screenAchievementsGallery.classList.remove('active');
      this.dockBtnFootprint.classList.add('active');
      this.dockBtnGallery.classList.remove('active');
      this.renderAll();
    } else {
      this.screenFootprint.classList.remove('active');
      this.screenAchievementsGallery.classList.add('active');
      this.dockBtnFootprint.classList.remove('active');
      this.dockBtnGallery.classList.add('active');
      this.renderTrophyRoom();
    }
  }

  renderAll() {
    this.currentMonthTitle.textContent = `${this.viewYear}年${this.viewMonth + 1}月`;
    this.renderCalendar();
    this.renderRecords();
    this.updateUserHeaderUI();
  }

  // ============================================
  // 1. 月曆熱力圖 (框線分色 + 8件漸進填滿，無xx件文字)
  // ============================================
  renderCalendar() {
    this.calendarGrid.innerHTML = '';

    const firstDayIndex = new Date(this.viewYear, this.viewMonth, 1).getDay();
    const daysInMonth = new Date(this.viewYear, this.viewMonth + 1, 0).getDate();
    const monthPrefix = `${this.viewYear}-${String(this.viewMonth + 1).padStart(2, '0')}`;

    const dayRecordsMap = {};
    this.records.forEach(r => {
      if (r.date.startsWith(monthPrefix)) {
        if (!dayRecordsMap[r.date]) dayRecordsMap[r.date] = [];
        dayRecordsMap[r.date].push(r);
      }
    });

    const todayStr = this.formatDate(new Date());

    for (let i = 0; i < firstDayIndex; i++) {
      const empty = document.createElement('div');
      empty.className = 'cal-day-cell empty';
      this.calendarGrid.appendChild(empty);
    }

    for (let day = 1; day <= daysInMonth; day++) {
      const dateStr = `${monthPrefix}-${String(day).padStart(2, '0')}`;
      const dayActs = dayRecordsMap[dateStr] || [];
      const totalCount = dayActs.length;

      const cell = document.createElement('button');
      cell.className = 'cal-day-cell';
      if (dateStr === todayStr) cell.classList.add('is-today');
      if (this.selectedDate === dateStr) cell.classList.add('selected');

      if (totalCount > 0) {
        cell.classList.add('has-activity');

        const typeCounts = { housework: 0, outing: 0, work: 0, health: 0 };
        dayActs.forEach(a => {
          if (typeCounts[a.type] !== undefined) typeCounts[a.type] += 1;
        });

        let dominantType = 'housework';
        let maxCnt = -1;
        for (const [t, cnt] of Object.entries(typeCounts)) {
          if (cnt > maxCnt) {
            maxCnt = cnt;
            dominantType = t;
          }
        }

        const themeColor = TYPE_CONFIG[dominantType].color;
        cell.style.borderColor = themeColor;

        const fillPercent = Math.min(100, Math.round((totalCount / 8) * 100));
        const fillOpacity = totalCount >= 8 ? 0.9 : (0.15 + (fillPercent / 100) * 0.55);

        const fillLayer = document.createElement('div');
        fillLayer.className = 'cal-day-fill';
        fillLayer.style.height = `${fillPercent}%`;
        fillLayer.style.background = themeColor;
        fillLayer.style.opacity = fillOpacity;
        cell.appendChild(fillLayer);

        if (totalCount >= 8) {
          cell.style.boxShadow = `0 0 12px ${themeColor}88`;
        }
      }

      const numSpan = document.createElement('span');
      numSpan.className = 'cal-day-num';
      numSpan.textContent = day;
      cell.appendChild(numSpan);

      cell.addEventListener('click', () => this.onCalendarDayClick(dateStr));

      this.calendarGrid.appendChild(cell);
    }
  }

  onCalendarDayClick(dateStr) {
    // 再次點擊已選中的日期：取消篩選並滾動生活足跡回頂部
    if (this.selectedDate === dateStr) {
      this.selectedDate = null;
      this.renderCalendar();
      this.renderRecords();
      if (this.recordsScrollContainer) {
        this.recordsScrollContainer.scrollTo({ top: 0, behavior: 'smooth' });
      }
      return;
    }

    this.selectedDate = dateStr;
    this.renderCalendar();

    const targetCard = document.getElementById(`group-${dateStr}`);
    if (targetCard && this.recordsScrollContainer) {
      document.querySelectorAll('.date-group-card').forEach(c => c.classList.remove('highlighted'));
      targetCard.classList.add('highlighted');

      // 僅滑動下方生活足跡容器，上方日曆固定不動！
      const containerRect = this.recordsScrollContainer.getBoundingClientRect();
      const cardRect = targetCard.getBoundingClientRect();
      const scrollOffset = cardRect.top - containerRect.top + this.recordsScrollContainer.scrollTop - 6;

      this.recordsScrollContainer.scrollTo({ top: scrollOffset, behavior: 'smooth' });
    } else if (!targetCard) {
      const parts = dateStr.split('-');
      if (confirm(`【${parts[0]}/${parts[1]}/${parts[2]}】這天目前沒有紀錄，\n要現在為這天補上一筆努力嗎？`)) {
        this.modalTargetDate = new Date(parseInt(parts[0], 10), parseInt(parts[1], 10) - 1, parseInt(parts[2], 10));
        this.openEntryModal();
      }
    }
  }



  // ============================================
  // 3. 每日生活足跡 (左滑刪除 + 點擊直接編輯)
  // ============================================
  renderRecords() {
    this.recordsContainer.innerHTML = '';

    const monthPrefix = `${this.viewYear}-${String(this.viewMonth + 1).padStart(2, '0')}`;
    let monthRecords = this.records.filter(r => r.date.startsWith(monthPrefix));

    const groups = {};
    monthRecords.forEach(r => {
      if (!groups[r.date]) groups[r.date] = [];
      groups[r.date].push(r);
    });

    const sortedDates = Object.keys(groups).sort((a, b) => new Date(b) - new Date(a));
    const weekdays = ['星期日', '星期一', '星期二', '星期三', '星期四', '星期五', '星期六'];

    if (sortedDates.length === 0) {
      this.recordsContainer.innerHTML = `
        <div style="text-align: center; padding: 48px 16px; color: #777788; font-weight: 700;">
          <div style="font-size: 32px; margin-bottom: 8px;">🌱</div>
          這個月還沒有記錄任何努力呢！<br>
          點擊下方「＋」按鈕，把今天做的事記下來吧！
        </div>
      `;
      return;
    }

    sortedDates.forEach(dateStr => {
      const items = groups[dateStr];
      const dObj = new Date(dateStr);
      const w = weekdays[dObj.getDay()];
      const formatted = dateStr.replace(/-/g, '/');

      const card = document.createElement('div');
      card.className = 'date-group-card';
      card.id = `group-${dateStr}`;
      if (this.selectedDate === dateStr) card.classList.add('highlighted');

      const headerDiv = document.createElement('div');
      headerDiv.className = 'date-group-title-bar';
      headerDiv.innerHTML = `
        <span class="date-group-date">${formatted} ${w}</span>
      `;
      card.appendChild(headerDiv);

      const itemsList = document.createElement('div');

      items.forEach(act => {
        const typeInfo = TYPE_CONFIG[act.type] || TYPE_CONFIG.housework;
        // 所有只要有備註的都直接取代原本選項的名字，一個框內單行顯示
        const displayText = (act.note && act.note.trim()) ? act.note.trim() : act.name;

        const swipeWrapper = document.createElement('div');
        swipeWrapper.className = 'record-swipe-wrapper';

        const deleteAction = document.createElement('button');
        deleteAction.className = 'record-swipe-delete-btn';
        deleteAction.innerHTML = `
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3 6 5 6 21 6"></polyline>
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
            <line x1="10" y1="11" x2="10" y2="17"></line>
            <line x1="14" y1="11" x2="14" y2="17"></line>
          </svg>
        `;
        deleteAction.title = '刪除此紀錄';

        deleteAction.addEventListener('click', (e) => {
          e.stopPropagation();
          if (confirm(`確定要刪除「${displayText}」這筆紀錄嗎？`)) {
            this.records = this.records.filter(r => r.id !== act.id);
            this.saveRecords();
            this.renderAll();
          }
        });

        const swipeContent = document.createElement('div');
        swipeContent.className = 'record-swipe-content';

        // 統一風格的向量線條 Icon + 單行文字呈現，完全移除時間與副標
        swipeContent.innerHTML = `
          <div class="item-main-row">
            <span class="item-line-icon" style="color: ${typeInfo.color}; background: ${typeInfo.color}18;">
              ${getIconSvg(act.icon, act.type)}
            </span>
            <span class="item-single-text">${displayText}</span>
          </div>
        `;

        this.bindSwipeAndClick(swipeWrapper, swipeContent, act);

        swipeWrapper.appendChild(deleteAction);
        swipeWrapper.appendChild(swipeContent);
        itemsList.appendChild(swipeWrapper);
      });

      card.appendChild(itemsList);
      this.recordsContainer.appendChild(card);
    });
  }

  bindSwipeAndClick(wrapper, content, act) {
    let startX = 0;
    let currentX = 0;
    let isSwiping = false;
    let hasMoved = false;

    const onStart = (clientX) => {
      startX = clientX;
      currentX = clientX;
      isSwiping = true;
      hasMoved = false;
    };

    const onMove = (clientX) => {
      if (!isSwiping) return;
      const diffX = clientX - startX;
      if (Math.abs(diffX) > 8) hasMoved = true;

      if (diffX < 0 && diffX >= -80) {
        content.style.transform = `translateX(${diffX}px)`;
      }
    };

    const onEnd = () => {
      if (!isSwiping) return;
      isSwiping = false;
      const diffX = currentX - startX;

      if (diffX <= -35) {
        wrapper.classList.add('swiped');
        content.style.transform = `translateX(-70px)`;
      } else {
        wrapper.classList.remove('swiped');
        content.style.transform = `translateX(0px)`;
      }
    };

    content.addEventListener('touchstart', (e) => onStart(e.touches[0].clientX), { passive: true });
    content.addEventListener('touchmove', (e) => {
      currentX = e.touches[0].clientX;
      onMove(e.touches[0].clientX);
    }, { passive: true });
    content.addEventListener('touchend', onEnd);

    content.addEventListener('mousedown', (e) => {
      onStart(e.clientX);
      const mouseMoveHandler = (ev) => {
        currentX = ev.clientX;
        onMove(ev.clientX);
      };
      const mouseUpHandler = () => {
        onEnd();
        window.removeEventListener('mousemove', mouseMoveHandler);
        window.removeEventListener('mouseup', mouseUpHandler);
      };
      window.addEventListener('mousemove', mouseMoveHandler);
      window.addEventListener('mouseup', mouseUpHandler);
    });

    content.addEventListener('click', () => {
      if (!hasMoved) {
        if (wrapper.classList.contains('swiped')) {
          wrapper.classList.remove('swiped');
          content.style.transform = `translateX(0px)`;
        } else {
          this.openEditModal(act);
        }
      }
    });
  }

  // ============================================
  // 4. 快速記錄彈窗 (常駐按鈕 + 暫時/常駐自訂)
  // ============================================
  openEntryModal() {
    this.modalEntry.classList.add('active');
    this.updateModalDateDisplay();
    this.renderPresetsGrid();
    this.renderModalTags();
  }

  closeEntryModal() {
    this.modalEntry.classList.remove('active');
  }

  updateModalDateDisplay() {
    const y = this.modalTargetDate.getFullYear();
    const m = String(this.modalTargetDate.getMonth() + 1).padStart(2, '0');
    const d = String(this.modalTargetDate.getDate()).padStart(2, '0');
    const weekdays = ['星期日', '星期一', '星期二', '星期三', '星期四', '星期五', '星期六'];
    const w = weekdays[this.modalTargetDate.getDay()];
    this.modalDateDisplay.textContent = `${y}/${m}/${d} ${w}`;
  }

  renderPresetsGrid() {
    const itemsHtml = this.presets.map(p => {
      const isSelected = this.selectedPreset.id === p.id;
      const isCustom = p.id.startsWith('custom_');
      const typeInfo = TYPE_CONFIG[p.type] || TYPE_CONFIG.housework;

      return `
        <div class="preset-chip ${isSelected ? 'active' : ''}" data-id="${p.id}" style="${isSelected ? `border-color: ${typeInfo.color}; background: ${typeInfo.color}18;` : ''}">
          <span class="preset-cat-tag">${typeInfo.shortName}</span>
          ${isCustom ? `<span class="preset-delete-dot" data-del-id="${p.id}" title="移除此常駐項目">✕</span>` : ''}
          <div class="preset-icon" style="color: ${typeInfo.color};">
            ${getIconSvg(p.icon, p.type)}
          </div>
          <span class="preset-name">${p.name}</span>
        </div>
      `;
    }).join('');

    const actionChipsHtml = `
      <div class="preset-chip action-chip" id="btnOpenTempCustom">
        <div class="preset-icon" style="color: #38BDF8;">
          ${getIconSvg('temp')}
        </div>
        <span class="preset-name">+ 暫時自訂</span>
      </div>
      <div class="preset-chip action-chip" id="btnOpenPermCustom">
        <div class="preset-icon" style="color: #A78BFA;">
          ${getIconSvg('perm')}
        </div>
        <span class="preset-name">+ 常駐自訂</span>
      </div>
    `;

    this.presetsGrid.innerHTML = itemsHtml + actionChipsHtml;

    this.presetsGrid.querySelectorAll('.preset-chip:not(.action-chip)').forEach(chip => {
      chip.addEventListener('click', (e) => {
        if (e.target.classList.contains('preset-delete-dot')) return;
        const p = this.presets.find(item => item.id === chip.dataset.id);
        if (p) {
          this.selectedPreset = p;
          this.inputCustomNote.value = ''; // 切換項目時清空自訂輸入
          this.renderPresetsGrid();
          this.renderModalTags();
        }
      });
    });

    this.presetsGrid.querySelectorAll('.preset-delete-dot').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const delId = btn.dataset.delId;
        const p = this.presets.find(item => item.id === delId);
        if (p && confirm(`確定要從常駐按鈕清單中移除「${p.name}」嗎？（已記錄的歷史足跡不會被刪除）`)) {
          this.presets = this.presets.filter(item => item.id !== delId);
          this.savePresets();
          if (this.selectedPreset.id === delId) {
            this.selectedPreset = this.presets[0];
          }
          this.renderPresetsGrid();
          this.renderModalTags();
        }
      });
    });

    // 點擊「+ 暫時自訂」與「+ 常駐自訂」打開同一個共用自訂彈窗
    const btnTemp = document.getElementById('btnOpenTempCustom');
    if (btnTemp) {
      btnTemp.addEventListener('click', () => this.openUnifiedCustomModal(false));
    }

    const btnPerm = document.getElementById('btnOpenPermCustom');
    if (btnPerm) {
      btnPerm.addEventListener('click', () => this.openUnifiedCustomModal(true));
    }
  }

  /**
   * 細節標籤渲染 (整合預設標籤與歷史寫過的標籤，點擊自動帶入備註)
   */
  renderModalTags() {
    const presetId = this.selectedPreset.id;
    const defaultTags = this.selectedPreset.tags || [this.selectedPreset.name];
    const historyTags = this.tagHistory[presetId] || [];

    // 合併並去重
    const allTags = Array.from(new Set([...defaultTags, ...historyTags]));

    this.modalTagsRow.innerHTML = allTags.map(tag => `
      <button class="quick-tag ${tag === this.inputCustomNote.value ? 'active' : ''}">${tag}</button>
    `).join('') + `<button class="quick-tag" id="btnAddTagItem">+ 標籤</button>`;

    // 核心修改：點擊標籤後自動寫在備註那裡！
    this.modalTagsRow.querySelectorAll('.quick-tag:not(#btnAddTagItem)').forEach(btn => {
      btn.addEventListener('click', () => {
        const clickedTag = btn.textContent;
        this.inputCustomNote.value = clickedTag;
        this.renderModalTags(); // 更新高亮
      });
    });

    const btnAdd = document.getElementById('btnAddTagItem');
    if (btnAdd) {
      btnAdd.addEventListener('click', () => {
        const val = prompt('輸入新標籤（會自動寫入備註並記住）：');
        if (val && val.trim()) {
          const cleanTag = val.trim();
          this.recordTagHistory(presetId, cleanTag);
          this.inputCustomNote.value = cleanTag;
          this.renderModalTags();
        }
      });
    }
  }

  // 記錄寫過的內容到標籤歷史庫中
  recordTagHistory(presetId, noteText) {
    if (!noteText || !noteText.trim()) return;
    const clean = noteText.trim();
    if (!this.tagHistory[presetId]) {
      this.tagHistory[presetId] = [];
    }
    if (!this.tagHistory[presetId].includes(clean)) {
      this.tagHistory[presetId].unshift(clean);
      if (this.tagHistory[presetId].length > 12) {
        this.tagHistory[presetId].pop();
      }
      this.saveTagHistory();
    }
  }

  onSavePresetRecord() {
    const now = new Date();
    const timeStr = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
    const dateStr = this.formatDate(this.modalTargetDate);

    const note = this.inputCustomNote.value.trim() || this.selectedPreset.name;

    // 記住使用者寫過的備註，下次自動變成常用細節標籤！
    this.recordTagHistory(this.selectedPreset.id, note);

    const newRecord = {
      id: 'act-' + Date.now(),
      date: dateStr,
      time: timeStr,
      name: this.selectedPreset.name,
      icon: this.selectedPreset.icon,
      type: this.selectedPreset.type,
      note: note
    };

    this.inputCustomNote.value = '';
    this.records.unshift(newRecord);
    this.saveRecords();
    this.closeEntryModal();

    this.viewYear = this.modalTargetDate.getFullYear();
    this.viewMonth = this.modalTargetDate.getMonth();

    // 保留目前生活足跡滾動位置，絕不跳動或自動滑至下方
    const prevScroll = this.recordsScrollContainer ? this.recordsScrollContainer.scrollTop : 0;
    this.renderAll();
    if (this.recordsScrollContainer) {
      this.recordsScrollContainer.scrollTop = prevScroll;
    }

    this.checkAchievements(true);
  }

  // ============================================
  // 5. 共用自訂項目彈窗 (暫時與常駐共用同一組件)
  // ============================================
  openUnifiedCustomModal(isPermanent) {
    this.modalUnifiedCustom.classList.add('active');
    this.inputCustomName.value = '';
    this.inputCustomDetailNote.value = '';

    // 依入口設定開關預設值
    this.chkSaveToPresets.checked = isPermanent;
    this.updateCustomModalUI();

    this.renderIconPicker();
  }

  closeUnifiedCustomModal() {
    this.modalUnifiedCustom.classList.remove('active');
  }

  updateCustomModalUI() {
    const isPermanent = this.chkSaveToPresets.checked;
    if (isPermanent) {
      this.unifiedCustomTitle.textContent = '＋ 新增常駐項目';
      this.btnSubmitCustomText.textContent = '加入常用清單並記錄';
      this.toggleSubhint.textContent = '勾選狀態：將此項目新增至預設按鈕，日後打開隨時可點！';
    } else {
      this.unifiedCustomTitle.textContent = '⚡ 暫時自訂（單次記錄）';
      this.btnSubmitCustomText.textContent = '記下這筆努力';
      this.toggleSubhint.textContent = '未勾選狀態：為「暫時自訂」，只記錄在今天，絕不佔用常用按鈕。';
    }
  }

  renderIconPicker() {
    const currentColor = TYPE_CONFIG[this.customType]?.color || '#10B981';
    this.customIconPickerGrid.innerHTML = AVAILABLE_ICONS.map(iconKey => `
      <button class="icon-pick-btn ${iconKey === this.customIcon ? 'active' : ''}" data-icon="${iconKey}" style="color: ${currentColor};" title="${iconKey}">
        ${getIconSvg(iconKey, this.customType)}
      </button>
    `).join('');

    this.customIconPickerGrid.querySelectorAll('.icon-pick-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        this.customIconPickerGrid.querySelectorAll('.icon-pick-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.customIcon = btn.dataset.icon;
      });
    });
  }

  onSubmitUnifiedCustom() {
    const name = this.inputCustomName.value.trim();
    if (!name) {
      alert('請填寫活動名稱！');
      return;
    }

    const isPermanent = this.chkSaveToPresets.checked;
    const note = this.inputCustomDetailNote.value.trim() || name;

    const now = new Date();
    const timeStr = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
    const dateStr = this.formatDate(this.modalTargetDate);

    // 如果使用者勾選加入常駐預設
    if (isPermanent) {
      const newPresetId = 'custom_' + Date.now();
      const newPreset = {
        id: newPresetId,
        name: name,
        icon: this.customIcon,
        type: this.customType,
        tags: [name, '搞定', '達成']
      };

      this.presets.push(newPreset);
      this.savePresets();
      this.selectedPreset = newPreset;
      this.recordTagHistory(newPresetId, note);
    }

    // 建立今日紀錄
    const newRecord = {
      id: 'act-' + Date.now(),
      date: dateStr,
      time: timeStr,
      name: name,
      icon: this.customIcon,
      type: this.customType,
      note: note
    };

    this.records.unshift(newRecord);
    this.saveRecords();

    this.closeUnifiedCustomModal();
    this.closeEntryModal();

    this.viewYear = this.modalTargetDate.getFullYear();
    this.viewMonth = this.modalTargetDate.getMonth();

    // 保留目前生活足跡滾動位置，絕不跳動或自動滑至下方
    const prevScroll = this.recordsScrollContainer ? this.recordsScrollContainer.scrollTop : 0;
    this.renderAll();
    if (this.recordsScrollContainer) {
      this.recordsScrollContainer.scrollTop = prevScroll;
    }

    this.checkAchievements(true);
  }

  // ============================================
  // 6. 點擊紀錄修改功能 (免筆圖示)
  // ============================================
  openEditModal(act) {
    this.editingRecordId = act.id;
    this.editingRecordType = act.type || 'housework';

    this.inputEditName.value = act.name;
    this.inputEditNote.value = act.note || '';

    this.editTypePicker.querySelectorAll('.type-pick-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.type === this.editingRecordType);
    });

    this.modalEditRecord.classList.add('active');
  }

  closeEditModal() {
    this.modalEditRecord.classList.remove('active');
    this.editingRecordId = null;
  }

  onSaveEditedRecord() {
    if (!this.editingRecordId) return;
    const name = this.inputEditName.value.trim();
    if (!name) {
      alert('名稱不能為空！');
      return;
    }

    const target = this.records.find(r => r.id === this.editingRecordId);
    if (target) {
      target.name = name;
      target.note = this.inputEditNote.value.trim() || name;
      target.type = this.editingRecordType;
      this.saveRecords();
      this.closeEditModal();
      this.renderAll();
    }
  }

  // ============================================
  // 7. 遊戲成就收藏室 (畫面 2 - 移除「解鎖條件:」字樣)
  // ============================================
  renderTrophyRoom() {
    const unlockedCount = this.achievements.filter(a => a.unlocked).length;
    const totalCount = this.achievements.length;
    const pct = Math.round((unlockedCount / totalCount) * 100);

    this.galleryProgressBadge.textContent = `${unlockedCount} / ${totalCount} 已解鎖`;
    this.galleryProgressPct.textContent = `${pct}%`;
    this.galleryProgressBar.style.width = `${pct}%`;

    this.trophyRoomGrid.innerHTML = this.achievements.map(ach => {
      if (ach.unlocked) {
        return `
          <div class="trophy-card unlocked">
            <div class="trophy-pedestal">${ach.icon}</div>
            <div class="trophy-name">${ach.name}</div>
            <div class="trophy-desc">${ach.desc}</div>
          </div>
        `;
      } else {
        // 未解鎖：暗化、隱藏名稱為 ???、直接顯示達成條件 (不含「解鎖條件:」)
        return `
          <div class="trophy-card locked">
            <div class="trophy-pedestal">🔒</div>
            <div class="trophy-name">???</div>
            <div class="trophy-desc">${ach.requirement}</div>
          </div>
        `;
      }
    }).join('');
  }

  // 頂部右上成就快速速覽彈窗 (同樣移除「解鎖條件:」)
  showQuickAchievementsModal() {
    const modal = document.createElement('div');
    modal.className = 'custom-preset-modal-overlay active';

    const listHtml = this.achievements.map(a => `
      <div style="display: flex; align-items: center; gap: 10px; padding: 10px; background: ${a.unlocked ? '#1E2522' : '#141418'}; border-radius: 10px; margin-bottom: 8px; border: 1.5px solid ${a.unlocked ? '#10B981' : '#2A2A34'}; opacity: ${a.unlocked ? '1' : '0.45'};">
        <div style="font-size: 24px;">${a.unlocked ? a.icon : '🔒'}</div>
        <div>
          <div style="font-size: 14px; font-weight: 800; color: ${a.unlocked ? '#FFF' : '#777'};">${a.unlocked ? a.name : '???'} ${a.unlocked ? '✅' : ''}</div>
          <div style="font-size: 11px; color: #888;">${a.unlocked ? a.desc : a.requirement}</div>
        </div>
      </div>
    `).join('');

    modal.innerHTML = `
      <div class="custom-preset-card">
        <div class="modal-header">
          <h3>🏆 成就速覽</h3>
          <button class="modal-close-btn" id="btnCloseQuickAchModal">✕</button>
        </div>
        <div class="modal-body-scroll">
          ${listHtml}
        </div>
      </div>
    `;

    document.body.appendChild(modal);
    modal.querySelector('#btnCloseQuickAchModal').addEventListener('click', () => modal.remove());
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.remove();
    });
  }

  // ============================================
  // 8. 成就檢查與即時吐司彈窗
  // ============================================
  checkAchievements(notify = false) {
    let newlyUnlocked = [];

    this.achievements.forEach(ach => {
      if (!ach.unlocked && ach.condition) {
        if (ach.condition(this.records)) {
          ach.unlocked = true;
          newlyUnlocked.push(ach);
        }
      }
    });

    if (newlyUnlocked.length > 0) {
      this.saveAchievements();
      if (notify) {
        newlyUnlocked.forEach(ach => this.triggerAchievementToast(ach));
      }
    }
  }

  triggerAchievementToast(ach) {
    const toast = document.createElement('div');
    toast.className = 'achievement-toast';
    toast.innerHTML = `
      <div class="toast-inner">
        <span class="toast-icon">${ach.icon}</span>
        <div class="toast-text">
          <div class="toast-title">🎉 解鎖生活成就！</div>
          <div class="toast-name">【${ach.name}】</div>
          <div class="toast-desc">${ach.desc}</div>
        </div>
      </div>
    `;
    document.body.appendChild(toast);
    setTimeout(() => toast.classList.add('show'), 50);
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 400);
    }, 4000);
  }

  // ============================================
  // 9. 帳號登入驗證、Google 官方登入與安全同步中心
  // ============================================
  initGoogleIdentity() {
    const isFile = window.location.protocol === 'file:';

    if (!window.google?.accounts?.id) {
      window.addEventListener('load', () => this.initGoogleIdentity(), { once: true });
      return;
    }

    // 若具備 Client ID 且非 file 協定，初始化官方 GSI
    if (this.googleClientId && !isFile) {
      try {
        google.accounts.id.initialize({
          client_id: this.googleClientId,
          callback: (res) => this.handleGoogleCredentialResponse(res),
          auto_select: false,
          cancel_on_tap_outside: true
        });

        if (this.googleRealBtnContainer) {
          this.googleRealBtnContainer.innerHTML = '';
          google.accounts.id.renderButton(
            this.googleRealBtnContainer,
            {
              theme: 'filled_black',
              size: 'large',
              type: 'standard',
              shape: 'rectangular',
              text: 'signin_with',
              logo_alignment: 'left',
              width: 300
            }
          );
          if (this.btnGoogleLogin) this.btnGoogleLogin.style.display = 'none';
        }
      } catch (err) {
        console.warn('Google GSI Init failed:', err);
      }
    } else {
      if (this.btnGoogleLogin) this.btnGoogleLogin.style.display = 'flex';
      if (this.googleRealBtnContainer) this.googleRealBtnContainer.innerHTML = '';
    }
  }

  triggerGoogleLoginAction() {
    if (window.google?.accounts?.id && this.googleClientId) {
      try {
        google.accounts.id.prompt();
      } catch (e) {
        console.warn('Google prompt error:', e);
      }
    }
  }

  handleGoogleCredentialResponse(response) {
    if (!response || !response.credential) {
      this.showAuthAlert('Google 授權失敗，未收到認證憑據。', 'error');
      return;
    }

    const payload = parseJwt(response.credential);
    if (!payload || !payload.email) {
      this.showAuthAlert('Google 憑證解析失敗。', 'error');
      return;
    }

    // 🛡️ 防禦坑 2：嚴格校驗 aud (受眾 Client ID)，拒絕跨 App 偽造攻擊
    if (payload.aud !== this.googleClientId) {
      this.showAuthAlert('安全防護攔截：此憑證非本應用簽發（aud 不相符），拒絕跨站偽造。', 'error');
      return;
    }

    // 🛡️ 防禦坑 2：驗證簽發者 (iss)
    const validIssuers = ['https://accounts.google.com', 'accounts.google.com'];
    if (!validIssuers.includes(payload.iss)) {
      this.showAuthAlert('安全防護攔截：此憑證非 Google 官方簽發 (iss 不符)。', 'error');
      return;
    }

    // 🛡️ 防禦坑 2：驗證過期時間 (exp)
    if (payload.exp && payload.exp * 1000 < Date.now()) {
      this.showAuthAlert('此 Google 登入憑證已過期，請重新嘗試登入。', 'error');
      return;
    }

    // 🛡️ 防禦坑 3：強制檢查 email_verified 必須為 true，避免帳號劫持
    if (!payload.email_verified) {
      this.showAuthAlert('此 Google 帳戶的電子郵件尚未完成 Google 官方驗證，無法登入。', 'error');
      return;
    }

    const { sub, email, name, picture } = payload;
    let users = this.loadUsers();
    let user = users.find(u => u.email.toLowerCase() === email.toLowerCase());

    if (!user) {
      user = {
        id: 'usr_g_' + sub,
        name: name || 'Google 使用者',
        email: email.toLowerCase(),
        avatar: picture || '',
        avatarLetter: name ? name.charAt(0).toUpperCase() : 'G',
        bgColor: '#3B82F6',
        provider: 'google',
        email_verified: true,
        googleSub: sub,
        createdAt: new Date().toISOString()
      };
      users.push(user);
    } else {
      // 既有帳號更新 Google 資訊，保留既有密碼與設定，不發生覆蓋劫持
      user.name = name || user.name;
      user.avatar = picture || user.avatar;
      user.email_verified = true;
      user.googleSub = sub;
      if (!user.provider) user.provider = 'google';
    }

    this.saveUsers(users);
    this.setCurrentUserAndSync(user);
    this.closeAuthModal();

    this.triggerAchievementToast({
      icon: '🎉',
      name: 'Google 官方安全授權成功',
      desc: `歡迎回來，${user.name}！已通過 aud 與 email_verified 安全檢驗。`
    });
  }

  updatePasswordStrengthUI(password) {
    if (!this.strengthMeter || !this.strengthLabel) return;
    const len = password.length;
    const hasLetter = /[a-zA-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecial = /[^a-zA-Z0-9]/.test(password);

    if (len === 0) {
      this.strengthMeter.className = 'strength-meter';
      this.strengthMeter.style.width = '0%';
      this.strengthLabel.textContent = '密碼強度：無';
    } else if (len < 6 || (!hasLetter && !hasNumber)) {
      this.strengthMeter.className = 'strength-meter';
      this.strengthMeter.style.width = '30%';
      this.strengthLabel.textContent = '密碼強度：弱';
    } else if (len >= 6 && hasLetter && hasNumber && !hasSpecial) {
      this.strengthMeter.className = 'strength-meter medium';
      this.strengthMeter.style.width = '65%';
      this.strengthLabel.textContent = '密碼強度：中';
    } else if (len >= 8 && hasLetter && hasNumber && hasSpecial) {
      this.strengthMeter.className = 'strength-meter strong';
      this.strengthMeter.style.width = '100%';
      this.strengthLabel.textContent = '密碼強度：極高';
    } else {
      this.strengthMeter.className = 'strength-meter medium';
      this.strengthMeter.style.width = '65%';
      this.strengthLabel.textContent = '密碼強度：中等';
    }
  }

  openAuthModal(mode = 'login') {
    this.authMode = mode;
    this.switchAuthMode(mode);
    if (this.authAlertBox) this.authAlertBox.style.display = 'none';
    if (this.inputAuthEmail) this.inputAuthEmail.value = '';
    if (this.inputAuthPassword) this.inputAuthPassword.value = '';
    if (this.inputAuthConfirmPassword) this.inputAuthConfirmPassword.value = '';
    if (this.inputAuthName) this.inputAuthName.value = '';
    if (this.modalAuth) this.modalAuth.classList.add('active');
    this.initGoogleIdentity();
  }

  closeAuthModal() {
    if (this.modalAuth) this.modalAuth.classList.remove('active');
  }

  switchAuthMode(mode) {
    this.authMode = mode;
    if (mode === 'login') {
      if (this.btnTabLogin) this.btnTabLogin.classList.add('active');
      if (this.btnTabRegister) this.btnTabRegister.classList.remove('active');
      if (this.groupRegisterName) this.groupRegisterName.style.display = 'none';
      if (this.groupRegisterConfirmPwd) this.groupRegisterConfirmPwd.style.display = 'none';
      if (this.pwdStrengthBar) this.pwdStrengthBar.style.display = 'none';
      if (this.txtSubmitAuth) this.txtSubmitAuth.textContent = '登入帳號';
    } else {
      if (this.btnTabLogin) this.btnTabLogin.classList.remove('active');
      if (this.btnTabRegister) this.btnTabRegister.classList.add('active');
      if (this.groupRegisterName) this.groupRegisterName.style.display = 'block';
      if (this.groupRegisterConfirmPwd) this.groupRegisterConfirmPwd.style.display = 'block';
      if (this.pwdStrengthBar) this.pwdStrengthBar.style.display = 'flex';
      if (this.txtSubmitAuth) this.txtSubmitAuth.textContent = '建立帳號並登入';
    }
    if (this.authAlertBox) this.authAlertBox.style.display = 'none';
  }

  showAuthAlert(message, type = 'error') {
    if (!this.authAlertBox) return;
    this.authAlertBox.textContent = message;
    this.authAlertBox.className = `auth-alert-box ${type}`;
    this.authAlertBox.style.display = 'block';
  }

  async submitEmailAuth() {
    const email = (this.inputAuthEmail.value || '').trim();
    const password = (this.inputAuthPassword.value || '').trim();
    const name = (this.inputAuthName.value || '').trim();

    // 格式嚴格校驗
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
      this.showAuthAlert('請輸入有效的電子信箱格式 (例如 user@gmail.com)');
      this.inputAuthEmail.focus();
      return;
    }

    if (!password || password.length < 6) {
      this.showAuthAlert('安全密碼長度需至少 6 個字元');
      this.inputAuthPassword.focus();
      return;
    }

    let users = this.loadUsers();

    if (this.authMode === 'register') {
      const confirmPwd = (this.inputAuthConfirmPassword.value || '').trim();
      if (password !== confirmPwd) {
        this.showAuthAlert('兩次密碼輸入不一致，請再次確認確認密碼');
        this.inputAuthConfirmPassword.focus();
        return;
      }

      const existing = users.find(u => u.email.toLowerCase() === email.toLowerCase());
      if (existing) {
        this.showAuthAlert('此信箱已註冊過帳號！請切換至「登入」分頁');
        return;
      }

      // 生成加密鹽與 SHA-256 密碼雜湊
      const salt = generateSecureSalt();
      const passwordHash = await hashPassword(password, salt);

      const newUser = {
        id: 'usr_e_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5),
        name: name || email.split('@')[0],
        email: email.toLowerCase(),
        salt: salt,
        passwordHash: passwordHash,
        email_verified: true,
        avatarLetter: (name || email).charAt(0).toUpperCase(),
        bgColor: '#10B981',
        provider: 'password',
        createdAt: new Date().toISOString()
      };

      users.push(newUser);
      this.saveUsers(users);

      this.closeAuthModal();
      this.setCurrentUserAndSync(newUser);

      this.triggerAchievementToast({
        icon: '🎉',
        name: '帳號建立成功',
        desc: `歡迎加入！已為您開通專屬記帳庫。`
      });

    } else {
      // 登入比對
      const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
      if (!user) {
        this.showAuthAlert('找不到此信箱帳號，請切換至「註冊新帳號」');
        return;
      }

      if (user.provider === 'google') {
        this.showAuthAlert('此帳號是以 Google 授權註冊，請點擊上方 Google 快速登入');
        return;
      }

      // 密碼安全雜湊比對
      let isValid = false;
      if (user.passwordHash && user.salt) {
        const testHash = await hashPassword(password, user.salt);
        isValid = (testHash === user.passwordHash);
      } else if (user.password) {
        // 舊測試資料相容比對
        isValid = (user.password === password);
      }

      if (!isValid) {
        this.showAuthAlert('密碼不正確，請重新輸入');
        this.inputAuthPassword.focus();
        return;
      }

      this.setCurrentUserAndSync(user);
      this.closeAuthModal();
      this.triggerAchievementToast({
        icon: '👋',
        name: '登入成功',
        desc: `歡迎回來，${user.name}！已安全驗證並同步足跡。`
      });
    }
  }

  setCurrentUserAndSync(user) {
    this.currentUser = user;
    this.saveCurrentUser(user);

    const newStorageKey = `life_records_${user.id}`;
    const newAchieveKey = `life_achieve_${user.id}`;

    // 資料遷移：若該使用者儲存庫尚無紀錄，但訪客有現有紀錄，自動繼承訪客現有資料
    const existingUserData = localStorage.getItem(newStorageKey);
    if (!existingUserData) {
      localStorage.setItem(newStorageKey, JSON.stringify(this.records));
    }

    this.storageKey = newStorageKey;
    this.achieveKey = newAchieveKey;

    this.records = this.loadRecords();
    this.achievements = this.loadAchievements();

    this.checkAchievements(false);
    this.updateUserHeaderUI();
    this.renderAll();
  }

  logoutUser() {
    this.currentUser = null;
    this.saveCurrentUser(null);

    this.storageKey = this.guestStorageKey;
    this.achieveKey = this.guestAchieveKey;

    this.records = this.loadRecords();
    this.achievements = this.loadAchievements();

    this.closeUserProfileModal();
    this.updateUserHeaderUI();
    this.renderAll();

    this.triggerAchievementToast({
      icon: '🔒',
      name: '已登出帳號',
      desc: '已切換回訪客模式，所有紀錄安全儲存在本機。'
    });
  }

  openUserProfileModal() {
    if (!this.currentUser) {
      this.openAuthModal('login');
      return;
    }

    if (this.profileLargeAvatar) {
      if (this.currentUser.avatar) {
        this.profileLargeAvatar.innerHTML = `<img src="${this.currentUser.avatar}" alt="${this.currentUser.name}">`;
        this.profileLargeAvatar.style.backgroundColor = 'transparent';
      } else {
        const letter = this.currentUser.avatarLetter || this.currentUser.name.charAt(0).toUpperCase();
        const bg = this.currentUser.bgColor || '#3B82F6';
        this.profileLargeAvatar.innerHTML = `<span>${letter}</span>`;
        this.profileLargeAvatar.style.backgroundColor = bg;
      }
    }

    if (this.profileDisplayName) this.profileDisplayName.textContent = this.currentUser.name;
    if (this.profileProviderTag) {
      if (this.currentUser.provider === 'google') {
        this.profileProviderTag.innerHTML = `🛡️ Google 官方認證`;
      } else {
        this.profileProviderTag.innerHTML = `🛡️ 信箱已安全驗證`;
      }
    }
    if (this.profileEmailText) this.profileEmailText.textContent = this.currentUser.email;

    if (this.profileStatRecords) this.profileStatRecords.textContent = this.records.length;
    const uniqueDays = new Set(this.records.map(r => r.date)).size;
    if (this.profileStatDays) this.profileStatDays.textContent = uniqueDays;
    const unlockedBadges = this.achievements.filter(a => a.unlocked).length;
    if (this.profileStatBadges) this.profileStatBadges.textContent = unlockedBadges;

    if (this.modalUserProfile) this.modalUserProfile.classList.add('active');
  }

  closeUserProfileModal() {
    if (this.modalUserProfile) this.modalUserProfile.classList.remove('active');
  }

  updateUserHeaderUI() {
    const applyToBtn = (circleEl, dotEl) => {
      if (!circleEl) return;
      if (this.currentUser) {
        if (this.currentUser.avatar) {
          circleEl.innerHTML = `<img src="${this.currentUser.avatar}" alt="${this.currentUser.name}">`;
          circleEl.style.backgroundColor = 'transparent';
        } else {
          const letter = this.currentUser.avatarLetter || this.currentUser.name.charAt(0).toUpperCase();
          const bg = this.currentUser.bgColor || '#3B82F6';
          circleEl.innerHTML = `<span>${letter}</span>`;
          circleEl.style.backgroundColor = bg;
          circleEl.style.color = '#FFF';
        }
        if (dotEl) dotEl.classList.add('online');
      } else {
        circleEl.innerHTML = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`;
        circleEl.style.backgroundColor = 'rgba(255, 255, 255, 0.1)';
        circleEl.style.color = '#FFF';
        if (dotEl) dotEl.classList.remove('online');
      }
    };

    applyToBtn(this.headerAvatarCircle, this.headerUserStatusDot);
    applyToBtn(this.headerAvatarCircleGallery, this.headerUserStatusDotGallery);
  }

  formatDate(d) {
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return `${y}-${m}-${day}`;
  }
}

window.addEventListener('DOMContentLoaded', () => {
  window.app = new LifeAchievementApp();
});
