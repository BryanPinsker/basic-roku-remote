import tkinter as tk
from tkinter import ttk
import requests
import socket
import re
import time

#Settings > System > Advanced system settings > Control by mobile apps -> Enable is required to be enabled on the Roku device
# This is a simple Roku remote control app using the External Control Protocol (ECP).
class RokuRemoteApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Roku Remote")

        self.discovered_rokus = []
        self.selected_roku_ip = tk.StringVar(value="")
        self.installed_channels = {}

        self.create_widgets()

        # ---- KEY BINDINGS FOR ARROW KEYS & SPACE BAR ----
        self.master.bind("<Up>",    lambda e: self.send_keypress("Up"))
        self.master.bind("<Down>",  lambda e: self.send_keypress("Down"))
        self.master.bind("<Left>",  lambda e: self.send_keypress("Left"))
        self.master.bind("<Right>", lambda e: self.send_keypress("Right"))
        # Space bar to toggle Play/Pause
        self.master.bind("<space>", lambda e: self.send_keypress("Play"))

    def create_widgets(self):
        top_frame = tk.Frame(self.master)
        top_frame.pack(pady=5, fill=tk.X)

        scan_button = tk.Button(top_frame, text="Scan for Rokus", command=self.scan_for_rokus)
        scan_button.pack(side=tk.LEFT, padx=5)

        self.roku_combo = ttk.Combobox(
            top_frame,
            textvariable=self.selected_roku_ip,
            width=30,
            state="readonly"
        )
        self.roku_combo.configure(takefocus=False)
        self.roku_combo.set("No Rokus discovered")
        self.roku_combo.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Bind the selection event to unfocus the combobox
        self.roku_combo.bind("<<ComboboxSelected>>", self.on_roku_selected)

        remote_frame = tk.LabelFrame(self.master, text="Remote Control")
        remote_frame.pack(pady=10, fill=tk.X)

        top_buttons_frame = tk.Frame(remote_frame)
        top_buttons_frame.pack()

        tk.Button(top_buttons_frame, text="Home", width=8,
                  command=lambda: self.send_keypress("Home")).pack(side=tk.LEFT, padx=5)
        tk.Button(top_buttons_frame, text="Back", width=8,
                  command=lambda: self.send_keypress("Back")).pack(side=tk.LEFT, padx=5)

        dpad_frame = tk.Frame(remote_frame)
        dpad_frame.pack(pady=10)

        tk.Button(dpad_frame, text="Up", width=8,
                  command=lambda: self.send_keypress("Up")).grid(row=0, column=1, pady=5)
        tk.Button(dpad_frame, text="Left", width=8,
                  command=lambda: self.send_keypress("Left")).grid(row=1, column=0, padx=5)
        tk.Button(dpad_frame, text="OK", width=8,
                  command=lambda: self.send_keypress("Select")).grid(row=1, column=1, padx=5)
        tk.Button(dpad_frame, text="Right", width=8,
                  command=lambda: self.send_keypress("Right")).grid(row=1, column=2, padx=5)
        tk.Button(dpad_frame, text="Down", width=8,
                  command=lambda: self.send_keypress("Down")).grid(row=2, column=1, pady=5)

        extra_buttons_frame = tk.Frame(remote_frame)
        extra_buttons_frame.pack()

        tk.Button(extra_buttons_frame, text="Info", width=8,
                  command=lambda: self.send_keypress("Info")).pack(side=tk.LEFT, padx=5)
        tk.Button(extra_buttons_frame, text="Star", width=8,
                  command=lambda: self.send_keypress("Star")).pack(side=tk.LEFT, padx=5)
        tk.Button(extra_buttons_frame, text="Replay", width=8,
                  command=lambda: self.send_keypress("InstantReplay")).pack(side=tk.LEFT, padx=5)

        transport_frame = tk.Frame(remote_frame)
        transport_frame.pack(pady=10)

        tk.Button(transport_frame, text="Rev", width=8,
                  command=lambda: self.send_keypress("Rev")).pack(side=tk.LEFT, padx=5)
        tk.Button(transport_frame, text="Play/Pause", width=8,
                  command=lambda: self.send_keypress("Play")).pack(side=tk.LEFT, padx=5)
        tk.Button(transport_frame, text="Fwd", width=8,
                  command=lambda: self.send_keypress("Fwd")).pack(side=tk.LEFT, padx=5)

        volume_frame = tk.Frame(remote_frame)
        volume_frame.pack(pady=10)

        tk.Button(volume_frame, text="Vol +", width=8,
                  command=lambda: self.send_keypress("VolumeUp")).pack(side=tk.LEFT, padx=5)
        tk.Button(volume_frame, text="Vol -", width=8,
                  command=lambda: self.send_keypress("VolumeDown")).pack(side=tk.LEFT, padx=5)
        tk.Button(volume_frame, text="Mute", width=8,
                  command=lambda: self.send_keypress("VolumeMute")).pack(side=tk.LEFT, padx=5)

        adv_frame = tk.LabelFrame(self.master, text="Advanced ECP Features")
        adv_frame.pack(pady=10, fill=tk.X)

        adv_btns_frame = tk.Frame(adv_frame)
        adv_btns_frame.pack(pady=5)

        tk.Button(adv_btns_frame, text="Get Device Info", command=self.get_device_info).pack(side=tk.LEFT, padx=5)
        tk.Button(adv_btns_frame, text="Refresh Apps", command=self.get_installed_channels).pack(side=tk.LEFT, padx=5)

        channel_launch_frame = tk.Frame(adv_frame)
        channel_launch_frame.pack(pady=5, fill=tk.X)

        self.channel_list_var = tk.StringVar()
        self.channel_combo = ttk.Combobox(
            channel_launch_frame,
            textvariable=self.channel_list_var,
            width=30,
            state="readonly"
        )
        self.channel_combo.set("No Apps loaded")
        self.channel_combo.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Bind the selection event to unfocus the combobox
        self.channel_combo.bind("<<ComboboxSelected>>", self.on_channel_selected)

        launch_button = tk.Button(channel_launch_frame, text="Launch App", command=self.launch_selected_channel)
        launch_button.pack(side=tk.LEFT, padx=5)

        self.log_text = tk.Text(self.master, height=6, width=60)
        self.log_text.pack(pady=5)

    def on_roku_selected(self, event):
        combo_str = self.roku_combo.get()
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", combo_str)
        if ip_match:
            ip = ip_match.group(1)
            self.selected_roku_ip.set(ip)
            self.log(f"Selected Roku IP: {ip}")
        else:
            self.log("No valid IP selected.")        
        self.master.focus_set()

    def on_channel_selected(self, event):
        self.master.focus_set()

    def send_keypress(self, keypress):
        ip = self.selected_roku_ip.get().strip()
        if not ip or ip.startswith("No Rokus"):
            self.log("No Roku selected.")
            return

        url = f"http://{ip}:8060/keypress/{keypress}"
        try:
            r = requests.post(url, timeout=2)
            if r.status_code == 200:
                self.log(f"Sent keypress '{keypress}' to {ip}")
            else:
                self.log(f"Keypress '{keypress}' error: HTTP {r.status_code}")
        except requests.exceptions.RequestException as e:
            self.log(f"Error sending {keypress} to {ip}: {e}")

    def get_device_info(self):
        ip = self.selected_roku_ip.get().strip()
        if not ip or ip.startswith("No Rokus"):
            self.log("No Roku selected.")
            return

        url = f"http://{ip}:8060/query/device-info"
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                self.log("Device Info:\n" + r.text)
            else:
                self.log(f"Device info request error: HTTP {r.status_code}")
        except requests.exceptions.RequestException as e:
            self.log(f"Error retrieving device info: {e}")

    def get_installed_channels(self):
        ip = self.selected_roku_ip.get().strip()
        if not ip or ip.startswith("No Rokus"):
            self.log("No Roku selected.")
            return

        url = f"http://{ip}:8060/query/apps"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200:
                apps_xml = r.text
                self.installed_channels = self.parse_roku_apps_xml(apps_xml)

                if self.installed_channels:
                    combo_values = [
                        f"{name} ({app_id})" for app_id, name in self.installed_channels.items()
                    ]
                    self.channel_combo['values'] = combo_values
                    self.channel_combo.set("Select an app to launch")
                    self.log(f"Loaded {len(self.installed_channels)} apps.")
                else:
                    self.channel_combo['values'] = []
                    self.channel_combo.set("No apps found")
                    self.log("No apps found on device.")
            else:
                self.log(f"Error: HTTP {r.status_code} retrieving apps.")
        except requests.exceptions.RequestException as e:
            self.log(f"Error retrieving apps: {e}")

    def parse_roku_apps_xml(self, xml_text):
        pattern = re.compile(r'<app id="(\d+)"[^>]*>([^<]+)</app>')
        apps = {}
        for match in pattern.finditer(xml_text):
            app_id = match.group(1)
            app_name = match.group(2)
            apps[app_id] = app_name
        return apps

    def launch_selected_channel(self):
        ip = self.selected_roku_ip.get().strip()
        if not ip or ip.startswith("No Rokus"):
            self.log("No Roku selected.")
            return

        combo_str = self.channel_combo.get()
        match = re.search(r"\((\d+)\)$", combo_str)
        if not match:
            self.log("Please select a valid channel.")
            return

        app_id = match.group(1)
        url = f"http://{ip}:8060/launch/{app_id}"
        try:
            r = requests.post(url, timeout=3)
            if r.status_code == 200:
                self.log(f"Launched channel: {combo_str}")
            else:
                self.log(f"Error launching channel (HTTP {r.status_code})")
        except requests.exceptions.RequestException as e:
            self.log(f"Error launching channel {app_id}: {e}")

    def scan_for_rokus(self):
        self.discovered_rokus = self.ssdp_discover_roku()
        if not self.discovered_rokus:
            self.roku_combo['values'] = []
            self.roku_combo.set("No Rokus discovered")
            self.log("No Rokus discovered.")
            return

        combo_values = []
        for friendly_name, ip in self.discovered_rokus:
            combo_values.append(f"{friendly_name} - {ip}")

        self.roku_combo['values'] = combo_values
        self.roku_combo.current(0)
        first_ip = self.discovered_rokus[0][1]
        self.selected_roku_ip.set(first_ip)
        self.log(f"Discovered {len(self.discovered_rokus)} Roku(s). Selected: {first_ip}")

    def ssdp_discover_roku(self, timeout=3):
        group = ("239.255.255.250", 1900)
        message = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            "ST: roku:ecp\r\n\r\n"
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

        discovered = {}
        try:
            sock.sendto(message.encode("utf-8"), group)
            start_time = time.time()
            while True:
                if time.time() - start_time > timeout:
                    break
                try:
                    data, _ = sock.recvfrom(65507)
                    response = data.decode("utf-8", errors="replace")

                    location_match = re.search(r"(?i)location:\s*(http://[^/]+)", response)
                    if location_match:
                        location_url = location_match.group(1).strip()
                        ip_match = re.search(r"http://([\d\.]+):8060", location_url)
                        if ip_match:
                            ip_addr = ip_match.group(1)
                            if ip_addr not in discovered:
                                friendly_name = self.get_roku_friendly_name(ip_addr)
                                discovered[ip_addr] = friendly_name
                except socket.timeout:
                    break
                except Exception as e:
                    self.log(f"SSDP discovery error: {e}")
                    break
        finally:
            sock.close()

        results = []
        for ip_addr, name in discovered.items():
            if not name:
                name = f"Roku at {ip_addr}"
            results.append((name, ip_addr))
        return results

    def get_roku_friendly_name(self, ip):
        try:
            url = f"http://{ip}:8060/query/device-info"
            resp = requests.get(url, timeout=2)
            if resp.status_code == 200:
                match = re.search(r"<friendly-device-name>([^<]+)</friendly-device-name>", resp.text)
                if match:
                    return match.group(1).strip()
        except Exception:
            pass
        return None

    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)


def main():
    root = tk.Tk()
    app = RokuRemoteApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
