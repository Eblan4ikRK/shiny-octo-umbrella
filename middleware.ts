// middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { Redis } from '@upstash/redis';
import { Ratelimit } from '@upstash/ratelimit';

// --- НАСТРОЙКИ ---

// 1. Список стран для блокировки (ISO 3166-1 alpha-2)
const BLOCKED_COUNTRIES: string[] = [
  'VN', 'CN', 'IN', 'PK', 'BR', 'ID', 'TH', 'TR', 'EG', 'SC', 'IR', 'NG', 'RU'
];

// 2. WHITELIST: Список разрешенных User-Agent. Пропускаем только их.
// Это защищает от простых ботов, скриптов и нестандартных клиентов.
const ALLOWED_USER_AGENTS: string[] = [
  // Основные браузеры
  'Chrome',   // Google Chrome, Brave, и другие на основе Chromium
  'Firefox',  // Mozilla Firefox
  'Safari',   // Apple Safari (важно не блокировать, много легитимных пользователей на iOS/macOS)
  'Edg',      // Microsoft Edge
  'OPR',      // Opera

  // Важные поисковые боты (для SEO)
  'Googlebot',
  'Bingbot',
  'Slurp',    // Yahoo
  'DuckDuckBot',
  'YandexBot',
];

// 3. Ограничение для ОДНОГО IP-адреса (Rate Limit)
const INDIVIDUAL_RATE_LIMIT = { requests: 10, window: '10 s' } as const;

// 4. Порог для определения атаки и отправки уведомления
const ATTACK_THRESHOLD = 10000; // 10,000 запросов
const ATTACK_TIME_WINDOW_SECONDS = 60; // за 60 секунд

// --- КОНЕЦ НАСТРОЕК ---


// Инициализация Redis (не трогать)
let redis: Redis | null = null;
let ratelimit: Ratelimit | null = null;

if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
  redis = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN,
  });

  ratelimit = new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(INDIVIDUAL_RATE_LIMIT.requests, INDIVIDUAL_RATE_LIMIT.window),
    analytics: true,
    prefix: 'ratelimit',
  });
} else {
  console.warn('Upstash Redis environment variables not found. Key security features are disabled.');
}


// Основная функция Middleware
export async function middleware(request: NextRequest) {
  // Если Redis не настроен, пропускаем все проверки безопасности
  if (!redis || !ratelimit) {
    return NextResponse.next();
  }

  const ip = request.ip ?? '127.0.0.1';
  const country = request.geo?.country;
  const userAgent = request.headers.get('user-agent') || '';

  // === НАЧАЛО ЦЕПОЧКИ ПРОВЕРОК ===

  // 1. Блокировка по стране
  if (country && BLOCKED_COUNTRIES.includes(country)) {
    await incrementBlockedCounter(redis);
    return new NextResponse(`Access from country ${country} is denied.`, { status: 403 });
  }
  
  // 2. Блокировка по User-Agent (пропускаем только тех, кто в белом списке)
  const isAllowedUserAgent = ALLOWED_USER_AGENTS.some(agent => userAgent.includes(agent));
  if (!isAllowedUserAgent) {
    await incrementBlockedCounter(redis);
    return new NextResponse('Your browser or bot is not allowed.', { status: 403 });
  }

  // 3. Индивидуальный Rate Limit по IP (самая дорогая проверка, идет последней)
  const { success } = await ratelimit.limit(ip);
  if (!success) {
    await incrementBlockedCounter(redis);
    return new NextResponse('Too many requests. Please try again later.', { status: 429 });
  }

  // === КОНЕЦ ЦЕПОЧКИ ПРОВЕРОК ===

  // 4. Детектор атак (срабатывает на ВСЕ запросы, прошедшие проверки)
  // Это позволяет отслеживать даже легитимный, но аномально высокий трафик
  const { totalRequests, blockedRequests } = await getAttackCounters(redis);

  if (totalRequests > ATTACK_THRESHOLD) {
    const notificationSent = await redis.get('notification_sent_flag');
    if (!notificationSent) {
      const passedRequests = totalRequests - blockedRequests;
      const attackStrength = (totalRequests / ATTACK_TIME_WINDOW_SECONDS).toFixed(1);

      const message = `🚨 *Обнаружена атака на сайт!* 🚨
      
- *Сила атаки:* ~${attackStrength} запросов/сек
- *Всего запросов за ${ATTACK_TIME_WINDOW_SECONDS} сек:* ${totalRequests}
- *Заблокировано (Geo/UA/RateLimit):* ${blockedRequests}
- *Прошло на сайт:* ${passedRequests}
      
Приняты автоматические меры по ограничению.`;

      await sendTelegramMessage(message);
      await redis.set('notification_sent_flag', 'true', { ex: ATTACK_TIME_WINDOW_SECONDS });
    }
  }

  return NextResponse.next();
}


// --- Вспомогательные функции (не изменять) ---

async function getAttackCounters(redis: Redis) {
    const pipe = redis.pipeline();
    const totalKey = 'attack:total';
    const blockedKey = 'attack:blocked';
  
    pipe.incr(totalKey);
    pipe.expire(totalKey, ATTACK_TIME_WINDOW_SECONDS, 'NX');
    pipe.get(blockedKey);
    pipe.expire(blockedKey, ATTACK_TIME_WINDOW_SECONDS, 'NX');
  
    const [_, __, blocked, ___] = await pipe.exec<[number, number, string | null, number]>();
    const currentTotal = await redis.get<number>(totalKey) ?? 1;
  
    return {
      totalRequests: currentTotal,
      blockedRequests: parseInt(blocked ?? '0'),
    };
}

async function incrementBlockedCounter(redis: Redis) {
  await redis.incr('attack:blocked');
}

async function sendTelegramMessage(text: string) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;

  if (!token || !chatId) {
    console.warn('Telegram credentials are not set. Cannot send notification.');
    return;
  }
  
  const url = `https://api.telegram.org/bot${token}/sendMessage`;
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text: text, parse_mode: 'Markdown' }),
    });
  } catch (error) {
    console.error('Failed to send Telegram message:', error);
  }
}

export const config = {
  matcher: '/((?!api|_next/static|_next/image|favicon.ico).*)',
};