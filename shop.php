<?php
/**
 * shop.php — Digiseller mini-shop (Enhanced UI + UX)
 * PHP 7.4/8+ (includes polyfill for str_contains)
 *
 * Features:
 *  - Category index -> products or child categories
 *  - Public products API with authenticated fallback (seller-goods)
 *  - Search + sort + pagination (best-effort across endpoints)
 *  - Cart add/list/update/clear -> redirect to official pay page
 *  - A11y-friendly, dark-mode aware, responsive UI
 */

declare(strict_types=1);

/* -------------------------- Polyfills (PHP 7.4) -------------------------- */
if (!function_exists('str_contains')) {
    function str_contains(string $haystack, string $needle): bool {
        return $needle === '' || strpos($haystack, $needle) !== false;
    }
}

/* -------------------------- Load config -------------------------- */
$cfgPath = __DIR__ . '/config.php';
if (!is_file($cfgPath)) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Missing config.php next to shop.php.\nCreate config.php with SELLER_ID, API_KEY, SECRET_KEY, LANG, CURRENCY, TIMEOUT.";
    exit;
}
require_once $cfgPath;

/* -------------------------- Security headers -------------------------- */
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Permissions-Policy: interest-cohort=()");
$connect = "https://api.digiseller.com https://shop.digiseller.ru https://pay.digiseller.ru https://oplata.info";
$csp = "default-src 'self'; img-src 'self' data: https:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; form-action 'self' https://oplata.info; connect-src 'self' $connect; frame-ancestors 'self'; base-uri 'self';";
header("Content-Security-Policy: $csp");

/* -------------------------- Session + CSRF -------------------------- */
ini_set('session.use_strict_mode', '1');
session_set_cookie_params([
    'lifetime' => 0, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax',
    'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
]);
if (session_status() !== PHP_SESSION_ACTIVE) session_start();

if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
function csrf_input(): string { return '<input type="hidden" name="csrf" value="'.htmlspecialchars($_SESSION['csrf']).'">'; }
function csrf_check(): void {
    if (($_POST['csrf'] ?? '') !== ($_SESSION['csrf'] ?? null)) {
        http_response_code(400);
        exit('Bad CSRF');
    }
}

/* -------------------------- Flash -------------------------- */
function flash_set(string $type, string $msg): void { $_SESSION["flash_$type"] = $msg; }
function flash_get(string $type): ?string { $k = "flash_$type"; $m = $_SESSION[$k] ?? null; unset($_SESSION[$k]); return $m; }

/* -------------------------- Helpers -------------------------- */
function h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function num($v, int $dec = 2): string { return number_format((float)$v, $dec, '.', ''); }

/** Multilingual field -> string (prefers LANG, falls back to short code, then first string) */
function ds_text($val): string {
    if (is_string($val)) return trim($val);
    if (is_array($val)) {
        $lang = defined('LANG') ? LANG : 'en-US';
        if (isset($val[$lang]) && is_string($val[$lang])) return trim($val[$lang]);
        $short = substr($lang, 0, 2);
        if (isset($val[$short]) && is_string($val[$short])) return trim($val[$short]);
        foreach ($val as $v) if (is_string($v) && trim($v) !== '') return trim($v);
    }
    return '';
}
/** Normalize id keys that differ per endpoint */
function ds_id(array $a): int {
    return (int)($a['id'] ?? $a['category_id'] ?? $a['good_id'] ?? $a['product_id'] ?? 0);
}
/** Currency-aware formatter (keeps non-breaking space before code) */
function money_fmt($amount, string $cur): string {
    $amount = (float)$amount;
    $dec = ($cur === 'JPY' ? 0 : 2);
    return num($amount, $dec) . '&nbsp;' . h($cur);
}

/* -------------------------- HTTP -------------------------- */
function http_get_json(string $url, array $query = [], array $headers = []): array {
    if ($query) $url .= (str_contains($url, '?') ? '&' : '?') . http_build_query($query);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => TIMEOUT,
        CURLOPT_HTTPHEADER => array_merge(['Accept: application/json'], $headers),
    ]);
    $body = curl_exec($ch);
    $err  = curl_error($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if ($err || $code >= 400) return ['error' => $err ?: "HTTP $code", 'url' => $url, 'raw' => (string)$body];
    $json = json_decode((string)$body, true);
    return is_array($json) ? $json : ['error' => 'Bad JSON', 'raw' => (string)$body];
}
function http_post_json(string $url, array $payload, array $headers = []): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => TIMEOUT,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_UNICODE),
        CURLOPT_HTTPHEADER => array_merge(['Accept: application/json','Content-Type: application/json'], $headers),
    ]);
    $body = curl_exec($ch);
    $err  = curl_error($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if ($err || $code >= 400) return ['error' => $err ?: "HTTP $code", 'raw' => (string)$body];
    $json = json_decode((string)$body, true);
    return is_array($json) ? $json : ['error' => 'Bad JSON', 'raw' => (string)$body];
}
function http_post_form(string $url, array $fields): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => TIMEOUT,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($fields),
        CURLOPT_HTTPHEADER => ['Accept: application/json', 'Content-Type: application/x-www-form-urlencoded'],
    ]);
    $body = curl_exec($ch);
    $err  = curl_error($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if ($err || $code >= 400) return ['error' => $err ?: "HTTP $code", 'raw' => (string)$body];
    $json = json_decode((string)$body, true);
    return is_array($json) ? $json : ['error' => 'Bad JSON', 'raw' => (string)$body];
}

/* -------------------------- Digiseller API client -------------------------- */
final class Digiseller {
    private ?string $token = null;
    private int $tokenExp = 0;

    private function token(): ?string {
        if ($this->token && $this->tokenExp > time()+60) return $this->token;
        $ts = time();
        $sign = hash('sha256', API_KEY . $ts); // sha256(apiKey + timestamp)
        $res = http_post_json('https://api.digiseller.com/api/apilogin', [
            'seller_id' => SELLER_ID,
            'timestamp' => $ts,
            'sign'      => $sign,
        ]);
        if (!empty($res['retval']) && (int)$res['retval'] !== 0) return null;
        $this->token = $res['token'] ?? null;
        $this->tokenExp = time() + 110*60; // token ≈120min
        return $this->token;
    }

    /** Category tree: rootId=0; cached for 5 minutes */
    function categories(int $root = 0): array {
        $key = "cats_$root";
        if (!empty($_SESSION[$key]) && $_SESSION[$key]['t'] > time()-300) {
            return $_SESSION[$key]['v'];
        }
        $res = http_get_json("https://api.digiseller.com/api/dictionary/categories/".SELLER_ID."/$root");
        $cats = $res['content'] ?? [];
        $_SESSION[$key] = ['t'=>time(),'v'=>$cats];
        return $cats;
    }

    /** Public products by category (+ paging), with authenticated fallback */
    function productsByCategory(int $categoryId, int $page = 1, int $per = 24, ?string $sort = null): array {
        // Try public endpoint first
        $pub = http_get_json('https://api.digiseller.com/api/shop/products', [
            'seller_id'   => SELLER_ID,
            'category_id' => $categoryId,
            'page'        => max(1,$page),
            'pagesize'    => min(100, max(10,$per)),
            'lang'        => LANG,
            // Some installations accept 'sort' (undocumented). No harm if ignored.
            'sort'        => $sort,
        ]);
        $products = $pub['products'] ?? [];

        if (!$products) {
            // Use authenticated fallback (returns richer data)
            $tok = $this->token();
            if ($tok) {
                $fallback = http_post_json(
                    'https://api.digiseller.com/api/seller-goods?token='.urlencode($tok),
                    [
                        'category_id'    => $categoryId,
                        'only_visible'   => true,
                        'only_available' => true,
                        'page'           => max(1,$page),
                        'pagesize'       => min(100, max(10,$per)),
                        'lang'           => LANG,
                        'sort'           => $sort,
                    ]
                );
                $goods = $fallback['goods'] ?? ($fallback['data'] ?? []);
                foreach ($goods as $g) {
                    $products[] = [
                        'id'       => $g['id']       ?? ($g['good_id'] ?? 0),
                        'name'     => $g['name']     ?? ($g['title'] ?? ''),
                        'image'    => $g['image']    ?? ($g['image_url'] ?? ''),
                        'price'    => $g['price']    ?? ($g['price_usd'] ?? ($g['price_rub'] ?? null)),
                        'currency' => $g['currency'] ?? ($g['price_currency'] ?? ''),
                        'prices'   => $g['prices']   ?? null,
                    ];
                }
            }
        }
        return $products;
    }

    /** Search products (best-effort across endpoints) */
    function searchProducts(string $query, int $page = 1, int $per = 24, ?string $sort = null): array {
        $query = trim($query);
        if ($query === '') return [];

        // Public search attempt (if supported by your account)
        $pub = http_get_json('https://api.digiseller.com/api/shop/products', [
            'seller_id' => SELLER_ID,
            'search'    => $query,
            'page'      => max(1,$page),
            'pagesize'  => min(100, max(10,$per)),
            'lang'      => LANG,
            'sort'      => $sort,
        ]);
        $products = $pub['products'] ?? [];

        // Fallback: authenticated "seller-goods" with 'query'/'name'
        if (!$products) {
            $tok = $this->token();
            if ($tok) {
                $fallback = http_post_json(
                    'https://api.digiseller.com/api/seller-goods?token='.urlencode($tok),
                    [
                        'query'          => $query, // many installs accept "query"
                        'name'           => $query, // and/or "name"
                        'only_visible'   => true,
                        'only_available' => true,
                        'page'           => max(1,$page),
                        'pagesize'       => min(100, max(10,$per)),
                        'lang'           => LANG,
                        'sort'           => $sort,
                    ]
                );
                $goods = $fallback['goods'] ?? ($fallback['data'] ?? []);
                foreach ($goods as $g) {
                    $products[] = [
                        'id'       => $g['id']       ?? ($g['good_id'] ?? 0),
                        'name'     => $g['name']     ?? ($g['title'] ?? ''),
                        'image'    => $g['image']    ?? ($g['image_url'] ?? ''),
                        'price'    => $g['price']    ?? ($g['price_usd'] ?? ($g['price_rub'] ?? null)),
                        'currency' => $g['currency'] ?? ($g['price_currency'] ?? ''),
                        'prices'   => $g['prices']   ?? null,
                    ];
                }
            }
        }
        return $products;
    }

    /* -------------------------- Cart -------------------------- */
    function cartAdd(int $productId, int $qty = 1): array {
        $uid = $_SESSION['cart_uid'] ?? '';
        $res = http_post_form('https://shop.digiseller.ru/xml/shop_cart_add.asp', [
            'product_id' => $productId,
            'product_cnt'=> max(1,$qty),
            'lang'       => LANG,
            'cart_uid'   => $uid,
        ]);
        if (empty($res['error']) && !empty($res['cart_uid'])) {
            $_SESSION['cart_uid'] = (string)$res['cart_uid'];
        }
        return $res;
    }
    function cartList(?int $itemId = null, ?int $qty = null): array {
        $uid = $_SESSION['cart_uid'] ?? '';
        if (!$uid) return ['cart_err'=>'0','cart_cnt'=>'0','products'=>[]];
        $fields = ['cart_uid'=>$uid, 'lang'=>LANG];
        if ($itemId !== null && $qty !== null) {
            $fields['item_id']     = $itemId;
            $fields['product_cnt'] = max(0,$qty);
        }
        return http_post_form('https://shop.digiseller.ru/xml/shop_cart_lst.asp', $fields);
    }
}
$api = new Digiseller();

/* -------------------------- UI Shell -------------------------- */
function ui_css(): string {
    return "
    :root{--c:#008cba;--bg:#f7f7fa;--bd:#e5e7eb;--tx:#283243;--accent:#f15a24}
    *{box-sizing:border-box}
    body{margin:0;font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;background:var(--bg);color:var(--tx)}
    .container{max-width:1100px;margin:20px auto;padding:16px;background:#fff;border:1px solid var(--bd);border-radius:14px}
    header{display:flex;flex-wrap:wrap;align-items:center;gap:12px;padding:10px 0 14px;border-bottom:1px solid var(--bd)}
    header h1{font-size:22px;margin:0}
    header nav{margin-left:auto;display:flex;gap:12px;align-items:center}
    .badge{background:var(--c);color:#fff;border-radius:999px;padding:.2rem .55rem;font-weight:600}
    .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px}
    .card{border:1px solid var(--bd);border-radius:12px;padding:12px;display:flex;flex-direction:column;gap:8px;transition:box-shadow .2s,transform .06s}
    .card:hover{box-shadow:0 10px 30px rgba(0,0,0,.08);transform:translateY(-1px)}
    .card h3{margin:.2rem 0;font-size:1.05rem}
    .btn{display:inline-flex;align-items:center;gap:.35rem;background:var(--c);color:#fff;padding:.58rem .9rem;border-radius:10px;text-decoration:none;font-weight:600;transition:filter .15s}
    .btn:focus,.btn:hover{filter:brightness(.95)}
    .btn.secondary{background:#eef1f5;color:#10243e}
    .btn.ghost{background:transparent;border:1px solid var(--bd);color:#10243e}
    .muted{color:#566}
    .row{display:flex;flex-wrap:wrap;gap:16px}
    .grow{flex:1 1 320px}
    .toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:12px 0 18px}
    .input{padding:.55rem .7rem;border:1px solid #ccd;border-radius:10px;min-width:200px}
    .select{padding:.55rem .7rem;border:1px solid #ccd;border-radius:10px}
    .table{width:100%;border-collapse:collapse}
    .table th,.table td{border-bottom:1px solid var(--bd);padding:.6rem .4rem;text-align:left}
    .right{text-align:right}
    .alert{padding:.8rem 1rem;border-radius:10px;margin:.6rem 0}
    .alert.err{background:#fee;border:1px solid #fbb}
    .alert.ok{background:#effaf3;border:1px solid #b7f0c1}
    .empty{padding:18px;border:1px dashed var(--bd);border-radius:12px;background:#fafcff}
    .breadcrumbs{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:10px 0}
    .crumb{color:#0b5cab;text-decoration:none}
    .crumb.sep{opacity:.4}
    .pager{display:flex;gap:8px;align-items:center;margin-top:12px}
    .pager input{width:64px}
    @media (prefers-color-scheme: dark){
      :root{--bg:#0b0e13;--bd:#243042;--tx:#e8eef7}
      .container{background:#121722;border-color:var(--bd)}
      .btn.ghost{color:#e8eef7;border-color:#384a63}
      .card{border-color:#243042}
      .empty{background:#0f1522;border-color:#233246}
    }";
}
function page(string $title, string $content, array $opts = []): void {
    $error = $opts['error'] ?? null;
    $success = $opts['success'] ?? null;
    $cartCnt = (int)($_SESSION['last_cart_cnt'] ?? 0);

    echo "<!doctype html><html lang='en'><head><meta charset='utf-8'>";
    echo "<meta name='viewport' content='width=device-width, initial-scale=1'>";
    echo "<title>".h($title)."</title>";
    if (is_file(__DIR__ . '/basic.css')) echo "<link rel='stylesheet' href='basic.css'>";
    echo "<style>".ui_css()."</style>";
    echo "</head><body><div class='container digiseller-body'>";
    echo "<header class='digiseller-row'><h1>My Digiseller Shop</h1>";
    echo "<nav><a class='btn' href='?route=home' aria-label='Home'>🏠 Home</a> ";
    echo "<a class='btn' href='?route=cart' aria-label='Cart'>🛒 Cart <span class='badge' id='cartBadge'>".$cartCnt."</span></a></nav></header>";

    if ($error)   echo "<div class='alert err'>".h($error)."</div>";
    if ($success) echo "<div class='alert ok'>".h($success)."</div>";
    if ($m = flash_get('error'))   echo "<div class='alert err'>".h($m)."</div>";
    if ($m = flash_get('success')) echo "<div class='alert ok'>".h($m)."</div>";

    echo $content;
    echo "<footer class='digiseller-row' style='margin-top:24px;padding-top:12px;border-top:1px solid var(--bd)'>
      <span class='muted'>Seller #".h((string)SELLER_ID)."</span>
      <span class='muted' style='margin-left:12px'>Language: ".h(LANG)."</span>
    </footer>";
    echo "</div></body></html>";
}

/* -------------------------- Router -------------------------- */
$route  = $_GET['route'] ?? 'home';
$method = $_SERVER['REQUEST_METHOD'];

/* Read common query controls */
$q      = isset($_GET['q']) ? trim((string)$_GET['q']) : '';
$sort   = $_GET['sort'] ?? '';                // 'price_asc'|'price_desc'|'' (best-effort)
$page   = max(1, (int)($_GET['p'] ?? 1));
$per    = min(60, max(12, (int)($_GET['per'] ?? 24)));

try {
    if ($route === 'home') {
        $cats = $api->categories(0);

        $toolbar = "<form class='toolbar' method='get' action=''>
          <input type='hidden' name='route' value='search'>
          <input class='input' type='search' name='q' placeholder='Search products…' value='".h($q)."' aria-label='Search'>
          <select class='select' name='sort' aria-label='Sort'>
            <option value=''>Sort: Default</option>
            <option ".($sort==='price_asc'?'selected':'')." value='price_asc'>Price ↑</option>
            <option ".($sort==='price_desc'?'selected':'')." value='price_desc'>Price ↓</option>
          </select>
          <select class='select' name='per' aria-label='Page size'>
            <option ".($per===12?'selected':'')." value='12'>12</option>
            <option ".($per===24?'selected':'')." value='24'>24</option>
            <option ".($per===36?'selected':'')." value='36'>36</option>
          </select>
          <button class='btn' type='submit'>🔎 Search</button>
        </form>";

        $html = "<section><h2>Categories</h2>".$toolbar."<div class='grid'>";
        foreach ($cats as $c) {
            $cid  = ds_id($c);
            $name = ds_text($c['name'] ?? ($c['title'] ?? '')) ?: ('Category #'.$cid);
            $html .= "<article class='card' aria-label='Category'>
                <h3>".h($name)."</h3>
                <a class='btn' href='?route=category&id=".$cid."'>Browse</a>
            </article>";
        }
        $html .= "</div></section>";
        page('Shop — Categories', $html);

    } elseif ($route === 'search') {
        $query = $q;
        $items = $api->searchProducts($query, $page, $per, $sort ?: null);
        $toolbar = "<form class='toolbar' method='get' action=''>
          <input type='hidden' name='route' value='search'>
          <input class='input' type='search' name='q' placeholder='Search products…' value='".h($query)."' aria-label='Search'>
          <select class='select' name='sort' aria-label='Sort'>
            <option value=''>Sort: Default</option>
            <option ".($sort==='price_asc'?'selected':'')." value='price_asc'>Price ↑</option>
            <option ".($sort==='price_desc'?'selected':'')." value='price_desc'>Price ↓</option>
          </select>
          <select class='select' name='per' aria-label='Page size'>
            <option ".($per===12?'selected':'')." value='12'>12</option>
            <option ".($per===24?'selected':'')." value='24'>24</option>
            <option ".($per===36?'selected':'')." value='36'>36</option>
          </select>
          <button class='btn' type='submit'>🔎 Search</button>
          <a class='btn ghost' href='?route=home'>← Categories</a>
        </form>";

        $html = "<section><h2>Search</h2>".$toolbar;

        if (!$items) {
            $html .= "<div class='empty'>No products found for “".h($query)."”. Try another keyword.</div>";
        } else {
            $html .= "<div class='grid'>";
            foreach ($items as $p) {
                $pid   = ds_id($p);
                $name  = ds_text($p['name'] ?? ($p['title'] ?? ''));
                $img   = $p['image'] ?? ($p['image_url'] ?? '');
                $currency = $p['currency'] ?? ($p['price_currency'] ?? '');
                $price = null;
                if (isset($p['price']))         $price = $p['price'];
                elseif (isset($p['price_usd'])) { $price = $p['price_usd']; $currency = $currency ?: 'USD'; }
                elseif (isset($p['price_rub'])) { $price = $p['price_rub']; $currency = $currency ?: 'RUB'; }
                elseif (isset($p['prices']) && is_array($p['prices'])) {
                    $cur = defined('CURRENCY') ? CURRENCY : 'USD';
                    $price = $p['prices'][$cur] ?? reset($p['prices']);
                    $currency = $cur;
                }
                $priceHtml = ($price!==null ? money_fmt($price, $currency ?: (defined('CURRENCY')?CURRENCY:'USD')) : "<span class='muted'>—</span>");

                $html .= "<article class='card'>
                    ".($img ? "<img alt='' src='".h($img)."' style='width:100%;height:140px;object-fit:cover;border-radius:8px'>" : "").
                    "<h3>".h($name ?: ('#'.$pid))."</h3>
                    <div class='row' style='justify-content:space-between;align-items:center'>
                      <div><strong>".$priceHtml."</strong></div>
                      <div>
                        <a class='btn' href='?route=product&id=$pid'>Details</a>
                        <a class='btn' href='?route=add&id=$pid'>Add</a>
                      </div>
                    </div>
                </article>";
            }
            $html .= "</div>";
        }

        // Simple pager controls (stateless; relies on your per/page query)
        $prev = max(1, $page-1); $next = $page+1;
        $html .= "<div class='pager'>
          <a class='btn ghost' href='?route=search&q=".urlencode($query)."&sort=".h($sort)."&per=$per&p=$prev'>&larr; Prev</a>
          <span class='muted'>Page $page</span>
          <a class='btn ghost' href='?route=search&q=".urlencode($query)."&sort=".h($sort)."&per=$per&p=$next'>Next &rarr;</a>
        </div>";

        $html .= "</section>";
        page('Shop — Search', $html);

    } elseif ($route === 'category') {
        $id   = (int)($_GET['id'] ?? 0);

        $cats = $api->categories(0);
        $catName = "Category #$id";
        foreach ($cats as $c) if (ds_id($c) === $id) { $catName = ds_text($c['name'] ?? ($c['title'] ?? '')); break; }

        // Controls
        $toolbar = "<form class='toolbar' method='get' action=''>
          <input type='hidden' name='route' value='category'>
          <input type='hidden' name='id' value='".$id."'>
          <input class='input' type='search' name='q' placeholder='Search in all products…' value='' aria-label='Search'>
          <select class='select' name='sort' aria-label='Sort'>
            <option value=''>Sort: Default</option>
            <option ".($sort==='price_asc'?'selected':'')." value='price_asc'>Price ↑</option>
            <option ".($sort==='price_desc'?'selected':'')." value='price_desc'>Price ↓</option>
          </select>
          <select class='select' name='per' aria-label='Page size'>
            <option ".($per===12?'selected':'')." value='12'>12</option>
            <option ".($per===24?'selected':'')." value='24'>24</option>
            <option ".($per===36?'selected':'')." value='36'>36</option>
          </select>
          <button class='btn' type='submit'>Apply</button>
          <a class='btn ghost' href='?route=home'>← Categories</a>
        </form>";

        // Breadcrumbs (lightweight)
        $crumbs = "<nav class='breadcrumbs'><a class='crumb' href='?route=home'>Home</a><span class='crumb sep'>/</span><span>".h($catName)."</span></nav>";

        $prods = $api->productsByCategory($id, $page, $per, $sort ?: null);

        $html = "<section><h2>".h($catName)."</h2>$crumbs$toolbar";

        if ($prods) {
            $html .= "<div class='grid'>";
            foreach ($prods as $p) {
                $pid   = ds_id($p);
                $name  = ds_text($p['name'] ?? ($p['title'] ?? ''));
                $img   = $p['image'] ?? ($p['image_url'] ?? '');
                $currency = $p['currency'] ?? ($p['price_currency'] ?? '');
                $price = null;
                if (isset($p['price']))         $price = $p['price'];
                elseif (isset($p['price_usd'])) { $price = $p['price_usd']; $currency = $currency ?: 'USD'; }
                elseif (isset($p['price_rub'])) { $price = $p['price_rub']; $currency = $currency ?: 'RUB'; }
                elseif (isset($p['prices']) && is_array($p['prices'])) {
                    $cur = defined('CURRENCY') ? CURRENCY : 'USD';
                    $price = $p['prices'][$cur] ?? reset($p['prices']);
                    $currency = $cur;
                }
                $priceHtml = ($price!==null ? money_fmt($price, $currency ?: (defined('CURRENCY')?CURRENCY:'USD')) : "<span class='muted'>—</span>");

                $html .= "<article class='card'>
                    ".($img ? "<img alt='' src='".h($img)."' style='width:100%;height:140px;object-fit:cover;border-radius:8px'>" : "").
                    "<h3>".h($name ?: ('#'.$pid))."</h3>
                    <div class='row' style='justify-content:space-between;align-items:center'>
                      <div><strong>".$priceHtml."</strong></div>
                      <div>
                        <a class='btn' href='?route=product&id=$pid'>Details</a>
                        <a class='btn' href='?route=add&id=$pid'>Add</a>
                      </div>
                    </div>
                </article>";
            }
            $html .= "</div>";

            $prev = max(1, $page-1); $next = $page+1;
            $html .= "<div class='pager'>
              <a class='btn ghost' href='?route=category&id=$id&sort=".h($sort)."&per=$per&p=$prev'>&larr; Prev</a>
              <span class='muted'>Page $page</span>
              <a class='btn ghost' href='?route=category&id=$id&sort=".h($sort)."&per=$per&p=$next'>Next &rarr;</a>
            </div>";
        } else {
            // No products: show children of this category
            $children = $api->categories($id);
            if ($children) {
                $html .= "<div class='empty'>No items directly in this category. Choose a subcategory:</div><div class='grid'>";
                foreach ($children as $child) {
                    $cid  = ds_id($child);
                    $name = ds_text($child['name'] ?? ($child['title'] ?? '')) ?: ('Category #'.$cid);
                    $html .= "<article class='card'>
                        <h3>".h($name)."</h3>
                        <a class='btn' href='?route=category&id=".$cid."'>Open</a>
                    </article>";
                }
                $html .= "</div>";
            } else {
                $html .= "<div class='empty'>This category is empty. Try another one.</div>";
            }
        }

        $html .= "</section>";
        page('Shop — '. $catName, $html);

    } elseif ($route === 'product') {
        $id = (int)($_GET['id'] ?? 0);
        $html = "<section class='row'>
            <div class='grow'>
              <h2>Product #$id</h2>
              <p class='muted'>A detailed product page can fetch options, galleries, and descriptions via Digiseller endpoints. For now, use Add to Cart below.</p>
              <div class='row'>
                <a class='btn' href='?route=add&id=$id'>🛒 Add to cart</a>
                <a class='btn ghost' href='javascript:history.back()'>← Back</a>
              </div>
            </div>
        </section>";
        page("Product #$id", $html);

    } elseif ($route === 'add') {
        $id = (int)($_GET['id'] ?? 0);
        if ($id <= 0) { flash_set('error', 'Invalid product id.'); header('Location: ?route=home'); exit; }
        $res = $api->cartAdd($id, 1);
        if (!empty($res['error'])) {
            flash_set('error', 'Add to cart failed.');
        } else {
            flash_set('success', 'Added to cart.');
            $_SESSION['last_cart_cnt'] = (int)($res['cart_cnt'] ?? ($_SESSION['last_cart_cnt'] ?? 0));
        }
        header('Location: ?route=cart'); exit;

    } elseif ($route === 'cart') {
        $cart = $api->cartList();
        $_SESSION['last_cart_cnt'] = (int)($cart['cart_cnt'] ?? 0);

        $html = "<section><h2>Your cart</h2>";
        if (empty($cart['products'])) {
            $html .= "<div class='empty'>Cart is empty.</div><p><a class='btn' href='?route=home'>Browse categories</a></p>";
        } else {
            $html .= "<form class='row' method='post' action='?route=clear_cart' onsubmit='return confirm(\"Clear cart?\")'>".csrf_input()."
                      <button class='btn secondary' type='submit'>🧹 Clear</button></form>";
            $html .= "<div class='row'><div class='grow'>";
            $html .= "<table class='table' role='table' aria-label='Cart items'>
                <thead><tr><th>Item</th><th class='right'>Price</th><th class='right'>Qty</th><th class='right'>Sum</th><th></th></tr></thead><tbody>";
            $grand = 0.0; $cur = '';
            foreach ($cart['products'] as $it) {
                $name = ds_text($it['name'] ?? 'Item');
                $price = (float)($it['price'] ?? 0);
                $qty   = (int)($it['cnt_item'] ?? 1);
                $sum   = $price * $qty;
                $cur   = (string)($it['currency'] ?? $cur);
                $itemId = (int)($it['item_id'] ?? 0);
                $grand += $sum;

                $html .= "<tr>
                    <td>".h($name)."</td>
                    <td class='right'>".money_fmt($price, $cur ?: CURRENCY)."</td>
                    <td class='right'>
                      <form method='post' action='?route=update_item' class='row' style='justify-content:flex-end;gap:6px'>
                        ".csrf_input()."
                        <input type='hidden' name='item_id' value='".(int)$itemId."'>
                        <input name='qty' type='number' min='0' step='1' value='".(int)$qty."' style='width:74px;padding:.35rem .5rem;border:1px solid #ccd;border-radius:8px'>
                        <button class='btn' type='submit'>Update</button>
                      </form>
                    </td>
                    <td class='right'>".money_fmt($sum, $cur ?: CURRENCY)."</td>
                    <td class='right'>
                      <form method='post' action='?route=update_item' onsubmit='return confirm(\"Remove item?\")'>
                        ".csrf_input()."
                        <input type='hidden' name='item_id' value='".(int)$itemId."'>
                        <input type='hidden' name='qty' value='0'>
                        <button class='btn ghost' type='submit' aria-label='Remove'>✖</button>
                      </form>
                    </td>
                </tr>";
            }
            $html .= "</tbody></table></div></div>";
            $html .= "<div class='row' style='justify-content:flex-end'>
                <div class='card' style='min-width:280px'>
                  <div class='row' style='justify-content:space-between'><strong>Total</strong><strong>".money_fmt($grand, $cur ?: CURRENCY)."</strong></div>
                  <form method='post' action='?route=checkout' style='margin-top:8px'>".csrf_input()."
                    <button class='btn' type='submit'>💳 Proceed to payment</button>
                  </form>
                </div>
              </div>";
        }
        $html .= "</section>";
        page('Your cart', $html);

    } elseif ($route === 'update_item' && $method === 'POST') {
        csrf_check();
        $itemId = (int)($_POST['item_id'] ?? 0);
        $qty    = (int)($_POST['qty'] ?? -1);
        if ($itemId <= 0 || $qty < 0) { flash_set('error', 'Bad item/qty.'); header('Location: ?route=cart'); exit; }
        $res = $api->cartList($itemId, $qty);
        if (!empty($res['error'])) flash_set('error', 'Update failed.');
        $_SESSION['last_cart_cnt'] = (int)($res['cart_cnt'] ?? 0);
        header('Location: ?route=cart'); exit;

    } elseif ($route === 'clear_cart' && $method === 'POST') {
        csrf_check();
        $cart = $api->cartList();
        if (!empty($cart['products'])) {
            foreach ($cart['products'] as $it) {
                $api->cartList((int)($it['item_id'] ?? 0), 0);
            }
        }
        unset($_SESSION['cart_uid']);
        $_SESSION['last_cart_cnt'] = 0;
        flash_set('success', 'Cart cleared.');
        header('Location: ?route=cart'); exit;

    } elseif ($route === 'checkout' && $method === 'POST') {
        csrf_check();
        $uid = $_SESSION['cart_uid'] ?? '';
        if (!$uid) { flash_set('error', 'Cart is empty.'); header('Location: ?route=cart'); exit; }
        $fields = [
            'cart_uid' => $uid,
            'typecurr' => CURRENCY,
            'lang'     => LANG,
            // 'email' => 'buyer@example.com', // optional
            // 'successpage' => 'https://your.site/success',
            // 'failpage'    => 'https://your.site/fail',
        ];
        echo "<!doctype html><meta charset='utf-8'><title>Redirecting…</title>";
        echo "<p style='font:16px/1.5 system-ui'>Redirecting to secure payment…</p>";
        echo "<form id='pay' action='https://oplata.info/asp2/pay.asp' method='post'>";
        foreach ($fields as $k=>$v) echo "<input type='hidden' name='".h($k)."' value='".h((string)$v)."'>";
        echo "</form><script>document.getElementById('pay').submit();</script>";
        exit;

    } elseif ($route === 'callback') {
        // Example signature check (adjust to your callback params)
        $incoming = [
            'amount'     => $_GET['amount']     ?? '',
            'currency'   => $_GET['currency']   ?? '',
            'invoice_id' => $_GET['invoice_id'] ?? '',
            'seller_id'  => $_GET['seller_id']  ?? '',
        ];
        ksort($incoming, SORT_STRING);
        $base = '';
        foreach ($incoming as $k=>$v) { $base .= "{$k}:{$v};"; }
        $calc = hash_hmac('sha256', $base, SECRET_KEY); // hex
        $ok   = hash_equals($calc, (string)($_GET['signature'] ?? ''));
        header('Content-Type: application/json');
        echo json_encode(['ok'=>$ok], JSON_UNESCAPED_UNICODE);
        exit;

    } else {
        http_response_code(404);
        page('Not found', "<p>Route not found.</p>");
    }
} catch (Throwable $e) {
    http_response_code(500);
    page('Error', "<div class='alert err'><strong>Unexpected error.</strong><br><small class='muted'>".$e->getMessage()."</small></div>");
}
