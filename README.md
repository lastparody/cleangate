# CleanGate (Adblock Core)

CleanGate, özellikle şifreli HTTPS trafiğindeki reklamları ve izleyicileri engellemek amacıyla tasarlanmış, tamamen bağımsız, yüksek performanslı bir "Adblock Proxy" çekirdeğidir. Go diliyle yazılmış olup, OpenGate veya herhangi bir dış proxy ile kusursuz bir "Zincirleme" (Proxy Chaining) yeteneğine sahiptir.

## Mimari ve Çalışma Mantığı

CleanGate, sisteminizde tek başına bir reklam engelleyici olarak çalışabileceği gibi, sansür aşma (DPI Bypass) araçlarıyla (Örn: OpenGate) harika bir uyum içinde çalışmak üzere tasarlanmıştır.

### 1. Proxy Chaining (Trafik Zincirleme)
CleanGate, internete doğrudan çıkmak yerine "Upstream Proxy" mantığını destekler. 
*   **Akış:** `Tarayıcı ➔ CleanGate (8081) ➔ OpenGate (8080) ➔ İnternet`
*   CleanGate paketleri alır, temizler ve DPI işlemlerinin yapılması için OpenGate'e paslar. Böylece iki uygulama birbirini görmeden kendi görevini eksiksiz yapar.

### 2. HTTPS ve MITM (Man-in-the-Middle)
İnternetin %95'i HTTPS (şifreli) olduğu için ağ seviyesindeki basit proxy'ler reklam kurallarındaki URL yollarını (Örn: `/ads.js`) göremezler. CleanGate bu engeli aşmak için anlık olarak çalışır:
1.  İlk açılışında bir **Root CA (Sertifika)** üretir.
2.  macOS (veya işletim sistemi) Keychain'ine (Anahtar Zinciri) bu sertifikayı otomatik güvenilir olarak yükler.
3.  Şifreli paketleri açar, URL'yi okuyup reklamsa `403 Forbidden` döner, değilse tek bir baytına bile dokunmadan hedefe (OpenGate'e) şeffaf şekilde iletir.

### 3. Akıllı Liste Motoru (Engine)
*   **Sabit Disk Önbelleği (Caching):** İndirilen reklam listeleri bilgisayarda `~/Library/Application Support/CleanGate/lists` konumunda saklanır. Program yeniden başladığında internet beklenmez, saniyeler içinde doğrudan diskten okunur.
*   **Tekrarlanma Filtresi (Deduplication):** Birden fazla liste yüklense bile aynı kural iki kez belleğe alınmaz. Hash Map kullanılarak %100 benzersiz (unique) kurallar süzülür, RAM tasarrufu sağlanır.
*   **Bant Genişliği Tasarrufu (If-Modified-Since & ETag):** Otomatik güncelleme sırasında sunucuya gidip "Dosya değişti mi?" diye sorar. `If-Modified-Since` başlığının yanı sıra modern `ETag` kontrolleri de yapılır. Çoğu sunucu (GitHub, Cloudflare vb.) bu başlıklardan birini destekler. Eğer sunucu desteklemezse ve her seferinde dosyayı sıfırdan verirse (`200 OK`), kodumuz arıza yapmadan yeni dosyayı sessizce indirip eskisinin üzerine yazar. Eğer dosya değişmediyse (`304 Not Modified`) indirme yapmaz, kotayı ve süreyi korur. Değiştiyse arka planda indirip "Sıfır Kesinti" (Hot-Swap) ile motoru yeniler. İnternet kesilirse veya sunucu çökerse dahi diskteki eski listelerle kusursuz çalışmaya devam eder.

## Komut Satırı Parametreleri (Flags)

CleanGate'i başlatırken (veya arayüz üzerinden çağırırken) kullanabileceğiniz parametreler şunlardır:

*   **`-addr`**: Proxy sunucusunun dinleyeceği yerel IP adresi. (Varsayılan: `127.0.0.1`)
*   **`-port`**: Proxy sunucusunun dinleyeceği port. (Varsayılan: `8081`)
*   **`-upstream`**: Temizlenen trafiğin aktarılacağı bir sonraki (Upstream) proxy adresi. Genellikle OpenGate'in adresidir. (Varsayılan: `127.0.0.1:8080`)
*   **`-system-proxy`**: CleanGate'in işletim sistemi vekil sunucusunu (System Proxy) kendi portuna ayarlayıp ayarlamayacağını belirler. (Varsayılan: `true`)
*   **`-lists`**: İndirilecek listelerin ID'leri (Katalog isimleri) veya virgülle ayrılmış tam URL'ler. (Varsayılan: `easylist,adguard`). Eğer tüm listeleri isterseniz `all` yazabilirsiniz.
    *   **Katalogdaki Temel ID'ler:** `easylist`, `adguard`, `ublock`, `peterlowe`, `easyprivacy`, `stevenblack`, `fanboy-annoy` vb. (Detaylar için `pkg/engine/lists.go` dosyasına bakınız)
*   **`-update-interval`**: Reklam listelerinin arka planda otomatik güncellenme sıklığı (Saat cinsinden). (Varsayılan: `24`)
*   **`-whitelist`**: Reklam filtresine ASLA sokulmayacak ve MITM işleminden muaf tutulacak alan adlarının listesi. (Örn: `garanti.com.tr`)

## Program Çıktıları (JSON İletişimi)

CleanGate (Go Core) durumu hakkında dışarıdaki UI / Arayüz uygulamalarına bilgi vermek için `stdout` üzerinden standart JSON formatında Event (olay) mesajları basar:

### Başarılı Başlatma (start)
```json
{
  "event": "start",
  "address": "127.0.0.1",
  "port": 8081,
  "upstream_proxy": "127.0.0.1:8080",
  "system_proxy_set": true
}
```

### Sertifika Yükleme Durumu (cert_status)
```json
{
  "event": "cert_status",
  "status": "installed", // veya "failed"
  "message": "Root CA successfully initialized"
}
```

### Listelerin Güncellenmesi (list_update)
(Önce `downloading` statusu fırlatılır, işlem bitince `success` ve okunan benzersiz kural sayısı verilir)
```json
{
  "event": "list_update",
  "status": "success",
  "total_rules": 74530
}
```

### Kapanış (stop)
```json
{
  "event": "stop",
  "cleanup_success": true
}
```
