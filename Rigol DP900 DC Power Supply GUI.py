import pyvisa
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from threading import Thread, Lock
import csv

class PowerSupplyApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Rigol DP900 Measurement")

        self.is_measuring = [False, False, False]
        self.log_files = [None, None, None]

        # Initialize VISA resource manager
        self.rm = pyvisa.ResourceManager()
        self.dp900 = None
        self.lock = Lock()  # Lock for thread-safe communication

        # Upper limits for parameters
        self.voltage_limits = [0, 0, 0]
        self.current_limits = [0, 0, 0]
        self.ocp_limits = [0, 0, 0]
        self.ovp_limits = [0, 0, 0]

        # Create a canvas
        self.canvas = tk.Canvas(master)
        self.scrollbar = ttk.Scrollbar(
            master, orient="vertical", command=self.canvas.yview
        )
        self.scrollable_frame = ttk.Frame(self.canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")),
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        ttk.Label(self.scrollable_frame, text="Select USB Instrument:").grid(
            row=0, column=0, padx=10, pady=10
        )
        self.instrument_selector = ttk.Combobox(self.scrollable_frame)
        self.instrument_selector.grid(row=0, column=1, padx=10, pady=10)
        self.refresh_instruments()

        self.connect_button = ttk.Button(
            self.scrollable_frame, text="Connect", command=self.connect_instrument
        )
        self.connect_button.grid(row=0, column=2, padx=10, pady=10)

        self.device_info_frame = ttk.LabelFrame(
            self.scrollable_frame, text="Device Information"
        )
        self.device_info_frame.grid(
            row=1, column=0, columnspan=3, padx=10, pady=10, sticky="ew"
        )

        # Manufacturer
        ttk.Label(self.device_info_frame, text="Manufacturer:").grid(
            row=0, column=0, sticky="w", padx=10, pady=5
        )
        self.manufacturer_label = ttk.Label(self.device_info_frame, text="")
        self.manufacturer_label.grid(
            row=0, column=1, columnspan=3, sticky="w", padx=5, pady=5
        )

        # Model
        ttk.Label(self.device_info_frame, text="Model:").grid(
            row=1, column=0, sticky="w", padx=5, pady=5
        )
        self.model_label = ttk.Label(self.device_info_frame, text="")
        self.model_label.grid(
            row=1, column=1, columnspan=3, sticky="w", padx=10, pady=10
        )

        # Serial Number
        ttk.Label(self.device_info_frame, text="Serial Number:").grid(
            row=2, column=0, sticky="w", padx=5, pady=5
        )
        self.serial_label = ttk.Label(self.device_info_frame, text="")
        self.serial_label.grid(
            row=2, column=1, columnspan=3, sticky="w", padx=5, pady=5
        )

        # Firmware Version
        ttk.Label(self.device_info_frame, text="Firmware Version:").grid(
            row=3, column=0, sticky="w", padx=10, pady=5
        )
        self.firmware_label = ttk.Label(self.device_info_frame, text="")
        self.firmware_label.grid(
            row=3, column=1, columnspan=3, sticky="w", padx=5, pady=5
        )

        self.channel_frames = []
        for ch in range(1, 4):
            frame = ttk.LabelFrame(self.scrollable_frame, text=f"Channel {ch}")
            frame.grid(row=2, column=ch - 1, padx=10, pady=10, sticky="n")

            ttk.Label(frame, text="Set Voltage (V):").grid(
                row=0, column=0, padx=10, pady=10
            )
            voltage = tk.DoubleVar(value=0.0)
            voltage_entry = ttk.Entry(frame, textvariable=voltage)
            voltage_entry.grid(row=0, column=1, padx=10, pady=10)

            ttk.Label(frame, text="Set Current (A):").grid(
                row=1, column=0, padx=10, pady=10
            )
            current = tk.DoubleVar(value=0.0)
            current_entry = ttk.Entry(frame, textvariable=current)
            current_entry.grid(row=1, column=1, padx=10, pady=10)

            ttk.Label(frame, text="Set OCP (A):").grid(
                row=2, column=0, padx=10, pady=10
            )
            ocp = tk.DoubleVar(value=0.0)
            ocp_entry = ttk.Entry(frame, textvariable=ocp)
            ocp_entry.grid(row=2, column=1, padx=10, pady=10)

            ttk.Label(frame, text="Set OVP (V):").grid(
                row=3, column=0, padx=10, pady=10
            )
            ovp = tk.DoubleVar(value=0.0)
            ovp_entry = ttk.Entry(frame, textvariable=ovp)
            ovp_entry.grid(row=3, column=1, padx=10, pady=10)

            set_button = ttk.Button(
                frame,
                text="Set Parameters",
                command=lambda ch=ch, v=voltage, c=current, o=ocp, ov=ovp: self.set_parameters(
                    ch, v, c, o, ov
                ),
            )
            set_button.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

            # On/Off buttons
            on_button = ttk.Button(
                frame,
                text="Turn On",
                command=lambda ch=ch: self.set_channel_state(ch, True),
            )
            on_button.grid(row=5, column=0, padx=10, pady=10)

            off_button = ttk.Button(
                frame,
                text="Turn Off",
                command=lambda ch=ch: self.set_channel_state(ch, False),
            )
            off_button.grid(row=5, column=1, padx=10, pady=10)

            # Measurement controls
            start_button = ttk.Button(
                frame,
                text="Start Measurement",
                command=lambda ch=ch: self.start_measurement(ch),
            )
            start_button.grid(row=6, column=0, padx=10, pady=10)

            stop_button = ttk.Button(
                frame,
                text="Stop Measurement",
                command=lambda ch=ch: self.stop_measurement(ch),
            )
            stop_button.grid(row=6, column=1, padx=10, pady=10)

            ttk.Label(frame, text="Log File:").grid(row=7, column=0, padx=10, pady=10)
            log_file_button = ttk.Button(
                frame,
                text="Select File",
                command=lambda ch=ch: self.select_log_file(ch),
            )
            log_file_button.grid(row=7, column=1, padx=10, pady=10)

            log_file_enable = tk.BooleanVar()
            log_file_checkbox = ttk.Checkbutton(
                frame, text="Enable Logging", variable=log_file_enable
            )
            log_file_checkbox.grid(row=8, column=0, columnspan=2, padx=10, pady=10)

            measurement_display = tk.Text(frame, width=30, height=10, state=tk.DISABLED)
            measurement_display.grid(row=9, column=0, columnspan=2, padx=10, pady=10)

            self.channel_frames.append(
                {
                    "frame": frame,
                    "voltage": voltage,
                    "current": current,
                    "ocp": ocp,
                    "ovp": ovp,
                    "set_button": set_button,
                    "on_button": on_button,
                    "off_button": off_button,
                    "start_button": start_button,
                    "stop_button": stop_button,
                    "log_file_button": log_file_button,
                    "log_file_checkbox": log_file_enable,
                    "measurement_display": measurement_display,
                }
            )

            # Disable controls until connected
            self.disable_controls(frame)

    def refresh_instruments(self):
        instruments = self.rm.list_resources()
        self.instrument_selector["values"] = instruments
        if instruments:
            self.instrument_selector.current(0)

    def connect_instrument(self):
        try:
            resource_string = self.instrument_selector.get()
            self.dp900 = self.rm.open_resource(resource_string)
            # Enable controls after successful connection
            for frame in self.channel_frames:
                self.enable_controls(frame["frame"])

            self.update_device_parameters()
            self.update_device_info()
            messagebox.showinfo("Info", "Connected to instrument successfully!")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect to instrument: {str(e)}")

    def update_device_info(self):
        try:
            with self.lock:  # Use the lock for thread-safe communication
                idn = self.dp900.query("*IDN?")
                parts = idn.split(",")
                if len(parts) >= 4:
                    manufacturer, model, serial_number, firmware_version = parts[:4]
                    self.manufacturer_label.config(text=manufacturer)
                    self.model_label.config(text=model)
                    self.serial_label.config(text=serial_number)
                    self.firmware_label.config(text=firmware_version)
                else:
                    messagebox.showerror(
                        "Error", "Unexpected device information format"
                    )
        except Exception as e:
            messagebox.showerror(
                "Error", f"Failed to retrieve device information: {str(e)}"
            )

    def update_device_parameters(self):
        for ch in range(1, 4):
            with self.lock:  # Use the lock for thread-safe communication
                voltage = float(self.dp900.query(f":SOURce{ch}:VOLTage?"))
                current = float(self.dp900.query(f":SOURce{ch}:CURRent?"))
                ocp = float(self.dp900.query(f":SOURce{ch}:CURRent:PROTection?"))
                ovp = float(self.dp900.query(f":SOURce{ch}:VOLTage:PROTection?"))

                # Query upper limits
                voltage_limit = float(
                    self.dp900.query(
                        f":SOURce{ch}:VOLTage:LEVel:IMMediate:AMPLitude? MAX"
                    )
                )
                current_limit = float(
                    self.dp900.query(
                        f":SOURce{ch}:CURRent:LEVel:IMMediate:AMPLitude? MAX"
                    )
                )
                ocp_limit = float(
                    self.dp900.query(f":SOURce{ch}:CURRent:PROTection:LEVel? MAX")
                )
                ovp_limit = float(
                    self.dp900.query(f":SOURce{ch}:VOLTage:PROTection:LEVel? MAX")
                )

            self.voltage_limits[ch - 1] = voltage_limit
            self.current_limits[ch - 1] = current_limit
            self.ocp_limits[ch - 1] = ocp_limit
            self.ovp_limits[ch - 1] = ovp_limit

            # Update the GUI with the current settings
            self.channel_frames[ch - 1]["voltage"].set(voltage)
            self.channel_frames[ch - 1]["current"].set(current)
            self.channel_frames[ch - 1]["ocp"].set(ocp)
            self.channel_frames[ch - 1]["ovp"].set(ovp)

            # Check and update button states
            self.update_button_states(ch)

    def check_channel_state(self, channel):
        with self.lock:  # Use the lock for thread-safe communication
            state_str = int(self.dp900.query(f":OUTPut:STATe? CH{channel}").strip())
        return state_str

    def update_button_states(self, channel):
        state = self.check_channel_state(channel)
        frame = self.channel_frames[channel - 1]
        frame["on_button"].state(["disabled"] if state else ["!disabled"])
        frame["off_button"].state(["!disabled"] if state else ["disabled"])

    def set_parameters(self, channel, voltage, current, ocp, ovp):
        voltage_val = voltage.get()
        current_val = current.get()
        ocp_val = ocp.get()
        ovp_val = ovp.get()

        if not (0 <= voltage_val <= self.voltage_limits[channel - 1]):
            messagebox.showerror(
                "Error", f"Voltage out of range (0-{self.voltage_limits[channel - 1]}V)"
            )
            return
        if not (0 <= current_val <= self.current_limits[channel - 1]):
            messagebox.showerror(
                "Error", f"Current out of range (0-{self.current_limits[channel - 1]}A)"
            )
            return
        if not (0 <= ocp_val <= self.ocp_limits[channel - 1]):
            messagebox.showerror(
                "Error", f"OCP out of range (0-{self.ocp_limits[channel - 1]}A)"
            )
            return
        if not (0 <= ovp_val <= self.ovp_limits[channel - 1]):
            messagebox.showerror(
                "Error", f"OVP out of range (0-{self.ovp_limits[channel - 1]}V)"
            )
            return

        try:
            with self.lock:  # Use the lock for thread-safe communication
                self.dp900.write(f":SOURce{channel}:VOLTage {voltage_val}")
                self.dp900.write(f":SOURce{channel}:CURRent {current_val}")
                self.dp900.write(f":SOURce{channel}:CURRent:PROTection {ocp_val}")
                self.dp900.write(f":SOURce{channel}:VOLTage:PROTection {ovp_val}")
            messagebox.showinfo("Info", "Parameters set successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to set parameters: {str(e)}")

    def set_channel_state(self, channel, state):
        try:
            with self.lock:  # Use the lock for thread-safe communication
                self.dp900.write(f":OUTPut:STATe CH{channel},{int(state)}")
            self.update_button_states(channel)
            messagebox.showinfo(
                "Info", f"Channel {channel} turned {'on' if state else 'off'}"
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to set channel state: {str(e)}")

    def select_log_file(self, channel):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv")]
        )
        if file_path:
            self.log_files[channel - 1] = file_path
            messagebox.showinfo(
                "Info", f"Log file selected for Channel {channel}: {file_path}"
            )

    def start_measurement(self, channel):
        if self.is_measuring[channel - 1]:
            messagebox.showwarning("Warning", f"Channel {channel} is already measuring")
            return

        self.is_measuring[channel - 1] = True
        measurement_thread = Thread(target=self.measurement_task, args=(channel,))
        measurement_thread.start()

    def stop_measurement(self, channel):
        self.is_measuring[channel - 1] = False

    def measurement_task(self, channel):
        display = self.channel_frames[channel - 1]["measurement_display"]
        log_file = (
            self.log_files[channel - 1]
            if self.channel_frames[channel - 1]["log_file_checkbox"].get()
            else None
        )

        if log_file:
            with open(log_file, mode="w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(["Time(ms)", "Voltage (V)", "Current (A)", "Power (W)"])
        start_time = time.time()

        while self.is_measuring[channel - 1]:
            try:
                with self.lock:  # Use the lock for thread-safe communication
                    current_time = int(
                        (time.time() - start_time) * 1000
                    )  # Time in milliseconds
                    voltage = float(self.dp900.query(f":MEASure:VOLTage? CH{channel}"))
                    current = float(self.dp900.query(f":MEASure:CURRent? CH{channel}"))
                    power = float(self.dp900.query(f":MEASure:POWer? CH{channel}"))
                self.update_button_states(channel)

                display.config(state=tk.NORMAL)
                display.insert(
                    tk.END, f"{current_time}ms, {voltage}V, {current}A, {power}W\n"
                )
                display.config(state=tk.DISABLED)

                if log_file:
                    with open(log_file, mode="a", newline="") as file:
                        writer = csv.writer(file)
                        writer.writerow([current_time, voltage, current, power])

                time.sleep(1)

            except Exception as e:
                display.config(state=tk.NORMAL)
                display.insert(tk.END, f"Error: {str(e)}\n")
                display.config(state=tk.DISABLED)
                self.stop_measurement(channel)
                break

    def disable_controls(self, frame):
        for child in frame.winfo_children():
            child.configure(state="disabled")

    def enable_controls(self, frame):
        for child in frame.winfo_children():
            child.configure(state="normal")


def main():
    root = tk.Tk()
    app = PowerSupplyApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
