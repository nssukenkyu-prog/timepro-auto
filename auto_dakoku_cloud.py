import time
import datetime
import os
import sys
from playwright.sync_api import sync_playwright

def run():
    print("---------------------------------")
    print("TimePro自動打刻システム (クラウド版) を起動中...")
    print("---------------------------------")

    # GitHub Secrets から環境変数経由でIDとパスワードを取得
    USER_ID = os.environ.get("TIMEPRO_USER_ID", "").strip()
    PASSWORD = os.environ.get("TIMEPRO_PASSWORD", "")

    if not USER_ID:
        print("エラー: 環境変数 TIMEPRO_USER_ID が設定されていません。")
        sys.exit(1)

    with sync_playwright() as p:
        # クラウド版は画面がない(headless=True)で実行
        browser = p.chromium.launch(headless=True)
        # タイムゾーンを日本時間に設定してコンテキストを作成
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            locale="ja-JP",
            timezone_id="Asia/Tokyo",
            viewport={"width": 1280, "height": 720}
        )
        
        page = context.new_page()

        print("日体大 TimePro-VG にアクセスしています...")
        try:
            page.goto("https://employ.nittai.ac.jp/TimePro-VG/page/Ovg00010t.aspx")
        except Exception as e:
            print("アクセスに失敗しました:", e)

        page.wait_for_load_state("networkidle")
        time.sleep(3)

        print("ログイン画面を探しています...")
        login_success = False

        for frame in [page.main_frame] + page.frames:
            try:
                user_input = frame.locator("input:not([type='hidden']):not([type='submit']):not([type='button']):not([type='password']):not([type='image'])").first
                
                if user_input.is_visible(timeout=1500):
                    print("「個人コード」の入力欄を発見しました！")
                    user_input.click()
                    user_input.fill(USER_ID)
                    
                    pass_input = frame.locator("input[type='password']").first
                    pass_input.fill(PASSWORD)

                    login_btn = frame.locator("input[type='image'][alt*='ログイン'], input[type='submit'], button:has-text('ログイン'), input[value*='ログイン']").first
                    
                    if login_btn.is_visible(timeout=1000):
                        login_btn.click()
                    else:
                        pass_input.press("Enter")
                        
                    print("ログイン処理を実行しました。")
                    login_success = True
                    break
            except Exception as e:
                continue

        if not login_success:
            print("⚠️ 【エラー】ログインの入力欄が見つかりませんでした。")
            context.close()
            browser.close()
            sys.exit(1)

        print("ログイン後の画面読み込みを待機しています...")
        page.wait_for_load_state("networkidle")
        time.sleep(8)

        t_delta = datetime.timedelta(hours=9)
        JST = datetime.timezone(t_delta, 'JST')
        now = datetime.datetime.now(JST)
        # 修正: 明示的に日本時間（JST）を取得して判定します
        if now.hour < 12:
            target_text = "出勤"
            selectors = [
                "input[value='出勤']", "input[value*='出勤']", "input#btn1",
                "img[src*='in']", "img[src*='IN']", "img[alt*='出勤']", "button:has-text('出勤')"
            ]
        else:
            target_text = "退勤"
            selectors = [
                "input[value='退勤']", "input[value*='退勤']", "input#btn2",
                "img[src*='out']", "img[src*='OUT']", "img[alt*='退勤']", "button:has-text('退勤')"
            ]

        print(f"[{now.strftime('%H:%M')}] {target_text} ボタンを探しています...")
        
        click_success = False

        for p_frame in context.pages:
            for frame in [p_frame.main_frame] + p_frame.frames:
                for selector in selectors:
                    try:
                        target_btn = frame.locator(selector).first
                        if target_btn.count() > 0:
                            target_btn.click(force=True, timeout=5000)
                            print(f"✅ 【成功】{target_text} の打刻をプログラム経由で実行しました！")
                            click_success = True
                            break
                    except:
                        continue
                if click_success:
                    break
            if click_success:
                break

        if not click_success:
            print("打刻画面が見つかりません。メニューの「クロッキング」をクリックして開きます...")
            menu_clicked = False
            for p_frame in context.pages:
                for frame in [p_frame.main_frame] + p_frame.frames:
                    try:
                        menu_btn = frame.locator("text='クロッキング', a[title*='クロッキング'], img[alt*='クロッキング']").first
                        if menu_btn.is_visible(timeout=1000):
                            print("「クロッキング」メニューをクリックします...")
                            menu_btn.click()
                            time.sleep(4)
                            menu_clicked = True
                            break
                    except Exception:
                        continue
                if menu_clicked:
                    break
            
            if menu_clicked:
                for p_frame in context.pages:
                    for frame in [p_frame.main_frame] + p_frame.frames:
                        for selector in selectors:
                            try:
                                target_btn = frame.locator(selector).first
                                if target_btn.count() > 0:
                                    target_btn.click(force=True, timeout=5000)
                                    print(f"✅ 【成功】{target_text} の打刻を実行しました！")
                                    click_success = True
                                    break
                            except:
                                continue
                        if click_success:
                            break
                    if click_success:
                        break

        if not click_success:
            print(f"⚠️ プログラムからの直接打刻に失敗しました。座標クリックを実行します。")
            page.screenshot(path="debug.png", full_page=True)
            print("スクリーンショットを debug.png に保存しました。")
            try:
                if target_text == "出勤":
                    for y in [580, 600, 620]:
                        page.mouse.click(60, y)
                        time.sleep(0.5)
                else:
                    for y in [580, 600, 620]:
                        page.mouse.click(150, y)
                        time.sleep(0.5)
                print(f"✅ 【成功】{target_text} の座標をクリックしました！")
                click_success = True
            except Exception as e:
                print("座標クリック中にエラーが発生しました:", e)

        print("処理が完了しました。")
        time.sleep(3)
        context.close()
        browser.close()

if __name__ == "__main__":
    try:
        run()
    except Exception as e:
        print(f"予期せぬエラーが発生しました: {e}")
        sys.exit(1)
