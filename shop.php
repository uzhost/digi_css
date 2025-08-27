<?php
/**
 * shop.php — Minimal Digiseller shop (PHP 8+)
 * - Requires: config.php with SELLER_ID, API_KEY, SECRET_KEY, LANG, CURRENCY, TIMEOUT
 * - No frameworks; cURL + sessions only.
 * - Cart stored by Digiseller (cart_uid in session).
 *
 * Routes:
 *   /shop.php?route=home                 — top categories
 *   /shop.php?route=category&id=123      — products in category
 *   /shop.php?route=product&id=456       — simple product view + Add
 *   /shop.php?route=add&id=456           — add to cart (qty=1)
 *   /shop.php?route=cart                 — view/update cart
 *   /shop.php?route=update_item          — POST item_id, qty (CSRF)
 *   /shop.php?route=clear_cart           — POST (CSRF) clear cart
 *   /shop.php?route=checkout             — POST -> auto-redirect to payment
 *   /shop.php?route=callback             — (optional) verify webhook signature
 */

declare(strict_types=1);

// ---------- Load config ----------
$cfgPath = __DIR__ . '/config.php';
if (!is_file($cfgPath)) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Missing config.php next to shop.php.\nPlease create config.php with SELLER_ID, API_KEY, SECRET_KEY, LANG, CURRENCY, TIMEOUT.";
    exit;
}
require_once $cfgPath;

// ---------- Security headers (liberal CSP to allow Digiseller domains) ----------
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Permissions-Policy: interest-cohort=()");
$nonce = bin2hex(random_bytes(8));
$connect = "https://api.digiseller.com https://shop.digiseller.ru https://pay.digiseller.ru https://oplata.info";
$csp = "default-src 'self'; img-src 'self' data: https:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; form-action 'self' https://oplata.info; connect-src 'self' $connect; frame-ancestors 'self'; base-uri 'self';";
header("Content-Security-Policy: $csp");

// ---------- Session (secure-ish) ----------
ini_set('session.use_strict_mode', '1');
session_set_cookie_params([
    'lifetime' => 0, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax',
    'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'
]);
if (session_status() !== PHP_SESSION_ACTIVE) session_start();

// ---------- CSRF ----------
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
function csrf_input(): string { return '<input type="hidden" name="csrf" value="'.htmlspecialchars($_SESSION['csrf']).'">'; }
function csrf_check(): void {
    if (($_POST['csrf'] ?? '') !== ($_SESSION['csrf'] ?? null)) {
        http_response_code(400);
        exit('Bad CSRF');
    }
}

// ---------- Flash ----------
function flash_set(string $type, string $msg): void { $_SESSION["flash_$type"] = $msg; }
function flash_get(string $type): ?string { $k = "flash_$type"; $m = $_SESSION[$k] ?? null; unset($_SESSION[$k]); return $m; }

// ---------- Helpers ----------
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
function num($v): string { return number_format((float)$v, 2, '.', ''); }

// ---------- HTTP ----------
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
    $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if ($err || $code >= 400) return ['error' => $err ?: "HTTP $code", 'url' => $url];
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
        CURLOPT_HTTPHEADER => array_merge([
            'Accept: application/json',
            'Content-Type: application/json',
        ], $headers),
    ]);
    $body = curl_exec($ch);
    $err  = curl_error($ch);
    $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
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
    $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if ($err || $code >= 400) return ['error' => $err ?: "HTTP $code", 'raw' => (string)$body];
    $json = json_decode((string)$body, true);
    return is_array($json) ? $json : ['error' => 'Bad JSON', 'raw' => (string)$body];
}

// ---------- Digiseller API client ----------
final class Digiseller {
    private ?string $token = null;
    private int $tokenExp = 0;

    private function token(): ?string {
        if ($this->token && $this->tokenExp > time()+60) return $this->token;
        $ts = time();
        $sign = hash('sha256', API_KEY . $ts); // sign = sha256(apiKey + timestamp)
        $res = http_post_json('https://api.digiseller.com/api/apilogin', [
            'seller_id' => SELLER_ID,
            'timestamp' => $ts,
            'sign'      => $sign,
        ]);
        if (!empty($res['retval']) && (int)$res['retval'] !== 0) return null;
        $this->token = $res['token'] ?? null;
        $this->tokenExp = time() + 110*60; // tokens are ~120min
        return $this->token;
    }

    // Category tree: rootId=0
    function categories(int $root = 0): array {
        // 5-minute session cache
        $key = "cats_$root";
        if (!empty($_SESSION[$key]) && $_SESSION[$key]['t'] > time()-300) {
            return $_SESSION[$key]['v'];
        }
        $url = "https://api.digiseller.com/api/dictionary/categories/".SELLER_ID."/$root";
        $res = http_get_json($url);
        $cats = $res['content'] ?? [];
        $_SESSION[$key] = ['t'=>time(),'v'=>$cats];
        return $cats;
    }

    // Public products by category
    function productsByCategory(int $categoryId, int $page = 1, int $per = 30): array {
        $res = http_get_json('https://api.digiseller.com/api/shop/products', [
            'seller_id'   => SELLER_ID,
            'category_id' => $categoryId,
            'page'        => max(1,$page),
            'pagesize'    => min(100, max(10,$per)),
            'lang'        => LANG,
        ]);
        return $res['products'] ?? [];
    }

    // Seller goods (auth; useful for richer fields if needed)
    function sellerGoods(array $filters = []): array {
        $tok = $this->token();
        if (!$tok) return ['error' => 'Token failed'];
        $q = ['token' => $tok];
        $res = http_post_json('https://api.digiseller.com/api/seller-goods?'.http_build_query($q), $filters);
        return $res['goods'] ?? ($res['data'] ?? $res);
    }

    // CART: add product, returns cart meta {cart_uid, cart_cnt, products:[...]}
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

    // CART: list or update quantity
    function cartList(?int $itemId = null, ?int $qty = null): array {
        $uid = $_SESSION['cart_uid'] ?? '';
        if (!$uid) return ['cart_err'=>'0','cart_cnt'=>'0','products'=>[]];
        $fields = ['cart_uid'=>$uid, 'lang'=>LANG];
        if ($itemId !== null && $qty !== null) {
            $fields['item_id'] = $itemId;
            $fields['product_cnt'] = max(0,$qty);
        }
        return http_post_form('https://shop.digiseller.ru/xml/shop_cart_lst.asp', $fields);
    }
}
$api = new Digiseller();

// ---------- UI shell ----------
function page(string $title, string $content, array $opts = []): void {
    $error = $opts['error'] ?? null;
    $success = $opts['success'] ?? null;
    $cartCnt = (int)($_SESSION['last_cart_cnt'] ?? 0);

    echo "<!doctype html><html lang='en'><head><meta charset='utf-8'>";
    echo "<meta name='viewport' content='width=device-width, initial-scale=1'>";
    echo "<title>".h($title)."</title>";
    // Optional external stylesheet
    if (is_file(__DIR__ . '/basic.css')) {
        echo "<link rel='stylesheet' href='basic.css'>";
    }
    // Minimal inline fallback for nicer cards if basic.css not present
    echo "<style>
      :root{--c:#008cba;--bg:#f7f7fa;--bd:#e5e7eb;--tx:#283243}
      body{margin:0;font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;background:var(--bg);color:var(--tx)}
      .container{max-width:1100px;margin:20px auto;padding:16px;background:#fff;border:1px solid var(--bd);border-radius:12px}
      header{display:flex;flex-wrap:wrap;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--bd)}
      header h1{font-size:22px;margin:0}
      header nav{margin-left:auto;display:flex;gap:12px;align-items:center}
      header .badge{background:var(--c);color:#fff;border-radius:999px;padding:.2rem .55rem;font-weight:600}
      .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px}
      .card{border:1px solid var(--bd);border-radius:12px;padding:12px;display:flex;flex-direction:column;gap:8px}
      .card h3{margin:.2rem 0;font-size:1.05rem}
      .btn{display:inline-flex;align-items:center;gap:.35rem;background:var(--c);color:#fff;padding:.55rem .8rem;border-radius:8px;text-decoration:none;font-weight:600}
      .btn:focus,.btn:hover{filter:brightness(.95)}
      .muted{color:#566}
      .row{display:flex;flex-wrap:wrap;gap:16px}
      .grow{flex:1 1 320px}
      .table{width:100%;border-collapse:collapse}
      .table th,.table td{border-bottom:1px solid var(--bd);padding:.6rem .4rem;text-align:left}
      .right{text-align:right}
      .alert{padding:.8rem 1rem;border-radius:10px;margin:.6rem 0}
      .alert.err{background:#fee;border:1px solid #fbb}
      .alert.ok{background:#effaf3;border:1px solid #b7f0c1}
      @media (prefers-color-scheme: dark){
        :root{--bg:#0b0e13;--bd:#243042;--tx:#e8eef7}
        .container{background:#121722;border-color:var(--bd)}
      }
    </style>";
    echo "</head><body>";
    echo "<div class='container digiseller-body'>";
    echo "<header class='digiseller-row'><h1>My Digiseller Shop</h1>";
    echo "<nav><a class='btn' href='?route=home' aria-label='Home'>🏠 Home</a> ";
    echo "<a class='btn' href='?route=cart' aria-label='Cart'>🛒 Cart <span class='badge' id='cartBadge'>".(int)$cartCnt."</span></a></nav></header>";

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

// ---------- Router ----------
$route = $_GET['route'] ?? 'home';
$method = $_SERVER['REQUEST_METHOD'];

try {
    if ($route === 'home') {
        $cats = $api->categories(0);
        $html = "<section><h2>Categories</h2><div class='grid'>";
        foreach ($cats as $c) {
            $html .= "<article class='card' aria-label='Category'>
                <h3>".h((string)$c['name'])."</h3>
                <a class='btn' href='?route=category&id=".intval($c['id'])."'>Browse</a>
            </article>";
        }
        $html .= "</div></section>";
        page('Shop — Categories', $html);

    } elseif ($route === 'category') {
        $id   = (int)($_GET['id'] ?? 0);
        $page = max(1, (int)($_GET['p'] ?? 1));
        $prods = $api->productsByCategory($id, $page);
        $cats  = $api->categories(0);
        $catName = "Category #$id";
        foreach ($cats as $c) if ((int)$c['id'] === $id) { $catName = (string)$c['name']; break; }

        $html = "<section><div class='row'><div class='grow'><h2>".h($catName)."</h2></div>
                 <div><a class='btn' href='?route=home'>← All categories</a></div></div>";
        if (!$prods) {
            $html .= "<p class='muted'>No products yet in this category.</p>";
        } else {
            $html .= "<div class='grid'>";
            foreach ($prods as $p) {
                $pid   = (int)($p['id'] ?? 0);
                $name  = (string)($p['name'] ?? ("#".$pid));
                // Try to guess a price field
                $price = $p['price'] ?? ($p['price_usd'] ?? ($p['price_rub'] ?? null));
                $currency = $p['currency'] ?? (isset($p['price_usd']) ? 'USD' : (isset($p['price_rub']) ? 'RUB' : ''));
                $img = $p['image'] ?? ($p['image_url'] ?? '');
                $html .= "<article class='card'>
                    ".($img ? "<img alt='' src='".h((string)$img)."' style='width:100%;height:140px;object-fit:cover;border-radius:8px'>":"").
                    "<h3>".h($name)."</h3>
                    <div class='row' style='justify-content:space-between;align-items:center'>
                      <div><strong>".($price!==null ? h(num($price))." ".h($currency) : "<span class='muted'>—</span>")."</strong></div>
                      <div>
                        <a class='btn' href='?route=product&id=$pid' aria-label='View product'>Details</a>
                        <a class='btn' href='?route=add&id=$pid' aria-label='Add to cart'>Add</a>
                      </div>
                    </div>
                </article>";
            }
            $html .= "</div>";
        }
        $html .= "</section>";
        page('Shop — '. $catName, $html);

    } elseif ($route === 'product') {
        $id = (int)($_GET['id'] ?? 0);
        // For a richer view you could call sellerGoods() with filters, or a product info endpoint.
        $html = "<section class='row'>
            <div class='grow'>
              <h2>Product #$id</h2>
              <p class='muted'>A detailed product page can fetch options, galleries, and descriptions via Digiseller endpoints. For now, use Add to Cart below.</p>
              <div class='row'>
                <a class='btn' href='?route=add&id=$id'>🛒 Add to cart</a>
                <a class='btn' href='javascript:history.back()'>← Back</a>
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
            $html .= "<p class='muted'>Cart is empty.</p><p><a class='btn' href='?route=home'>Browse categories</a></p>";
        } else {
            $html .= "<form class='row' method='post' action='?route=clear_cart' onsubmit='return confirm(\"Clear cart?\")'>".csrf_input()."
                      <button class='btn' type='submit'>🧹 Clear</button></form>";
            $html .= "<div class='row'><div class='grow'>";
            $html .= "<table class='table' role='table' aria-label='Cart items'>
                <thead><tr><th>Item</th><th class='right'>Price</th><th class='right'>Qty</th><th class='right'>Sum</th><th></th></tr></thead><tbody>";
            $grand = 0.0; $cur = '';
            foreach ($cart['products'] as $it) {
                $name = (string)($it['name'] ?? 'Item');
                $price = (float)($it['price'] ?? 0);
                $qty   = (int)($it['cnt_item'] ?? 1);
                $sum   = $price * $qty;
                $cur   = (string)($it['currency'] ?? $cur);
                $itemId = (int)($it['item_id'] ?? 0); // Digiseller returns per-cart item id
                $grand += $sum;

                $html .= "<tr>
                    <td>".h($name)."</td>
                    <td class='right'>".h(num($price))." ".h($cur)."</td>
                    <td class='right'>
                      <form method='post' action='?route=update_item' class='row' style='justify-content:flex-end;gap:6px'>
                        ".csrf_input()."
                        <input type='hidden' name='item_id' value='".(int)$itemId."'>
                        <input name='qty' type='number' min='0' step='1' value='".(int)$qty."' style='width:74px;padding:.35rem .5rem;border:1px solid #ccd;border-radius:8px'>
                        <button class='btn' type='submit'>Update</button>
                      </form>
                    </td>
                    <td class='right'>".h(num($sum))." ".h($cur)."</td>
                    <td class='right'>
                      <form method='post' action='?route=update_item' onsubmit='return confirm(\"Remove item?\")'>
                        ".csrf_input()."
                        <input type='hidden' name='item_id' value='".(int)$itemId."'>
                        <input type='hidden' name='qty' value='0'>
                        <button class='btn' type='submit' aria-label='Remove'>✖</button>
                      </form>
                    </td>
                </tr>";
            }
            $html .= "</tbody></table></div></div>";
            $html .= "<div class='row' style='justify-content:flex-end'>
                <div class='card' style='min-width:280px'>
                  <div class='row' style='justify-content:space-between'><strong>Total</strong><strong>".h(num($grand))." ".h($cur ?: CURRENCY)."</strong></div>
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
        // Best-effort: set all items to 0
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
        // Auto-POST to Digiseller payment page
        $fields = [
            'cart_uid' => $uid,
            'typecurr' => CURRENCY, // currency on the payment page
            'lang'     => LANG,
            // Optional: 'email' => 'buyer@example.com',
            // Optional redirects: 'failpage' | 'successpage'
        ];
        echo "<!doctype html><meta charset='utf-8'><title>Redirecting…</title>";
        echo "<p style='font:16px/1.5 system-ui'>Redirecting to secure payment…</p>";
        echo "<form id='pay' action='https://oplata.info/asp2/pay.asp' method='post'>";
        foreach ($fields as $k=>$v) echo "<input type='hidden' name='".h($k)."' value='".h((string)$v)."'>";
        echo "</form><script>document.getElementById('pay').submit();</script>";
        exit;

    } elseif ($route === 'callback') {
        // Example signature check (adjust according to your callback parameters)
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
