import tkinter as tk
from tkinter import ttk, messagebox, filedialog, font as tkfont
import json
import os
import sys
import locale
from datetime import datetime
import random
import string
import struct
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Sakana Toolkit")
        # 设置初始窗口尺寸为1280×720
        self.root.geometry("1280x720")
        # 设置窗口最小尺寸
        self.root.minsize(1024, 576)
        
        # 程序元信息
        self.version = "0.1.0.8"
        self.author = "KArabella"
        
        # 初始化基本属性
        self.history = []
        self.custom_mappings = {}
        
        # 初始化本地化系统（先加载默认语言包）
        self.language_packs = {
            "zh_CN": self._load_default_chinese(),
            "en_US": self._load_default_english()
        }
        
        # 检测系统语言并设置当前语言
        self.current_language = self._detect_system_language()
        
        # 初始化程序目录结构
        self._init_program_directory()
        
        # 初始化历史记录文件
        self._init_history_file()
        
        # 加载额外本地化文件（会合并到现有语言包）
        self._load_localization_files()
        
        # 加载设置（可能会覆盖当前语言）
        self.settings = self._load_settings()
        if 'language' in self.settings:
            self.current_language = self.settings['language']
        
        # 加载自定义映射
        self.load_custom_mappings()
        
        # 设置现代风格
        self.style = ttk.Style()
        self.style.configure('.', font=('Bender', 10))
        self.style.configure('TNotebook.Tab', font=('Arial', 10, 'bold'))
        self.style.configure('Title.TLabel', font=('Arial', 12, 'bold'))
        
        # 创建主标签页
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # 创建设置页
        self._setup_settings_tab()
        
        # 创建凯撒密码标签页
        self._setup_caesar_tab()
        
        # 创建文件嵌入工具标签页
        self._setup_file_embed_tab()
        
        # 确保设置页在最前
        self.notebook.select(0)
        
        # 初始化后更新UI语言
        self._update_ui_language()

                # 新增摩斯电码相关变量
        self.morse_code_dict = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
            'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
            'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
            'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
            'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
            '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
            '8': '---..', '9': '----.', '.': '.-.-.-', ',': '--..--', '?': '..--..',
            "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-',
            '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.',
            '-': '-....-', '_': '..--.-', '"': '.-..-.', '$': '...-..-', '@': '.--.-.',
            ' ': '/'
        }
        # 反向字典
        self.reverse_morse_dict = {v: k for k, v in self.morse_code_dict.items()}

    def _setup_morse_tab(self):
        """摩斯电码标签页"""
        self.morse_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.morse_tab, text=self._tr("Morse Code"))
        
        # 操作模式选择
        mode_frame = ttk.LabelFrame(self.morse_tab, text=self._tr("Operation Mode"))
        mode_frame.pack(fill="x", padx=10, pady=5)
        
        self.morse_mode_var = tk.StringVar(value="text")
        ttk.Radiobutton(mode_frame, text=self._tr("Text Mode"), variable=self.morse_mode_var, 
                       value="text", command=self._toggle_morse_mode).pack(side="left", padx=5)
        ttk.Radiobutton(mode_frame, text=self._tr("Audio Mode"), variable=self.morse_mode_var, 
                       value="audio", command=self._toggle_morse_mode).pack(side="left", padx=5)
        
        # 文本模式组件
        self.text_mode_frame = ttk.Frame(self.morse_tab)
        self.text_mode_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # 输入输出区域
        io_frame = ttk.Frame(self.text_mode_frame)
        io_frame.pack(fill="both", expand=True)
        
        ttk.Label(io_frame, text=self._tr("Input:")).grid(row=0, column=0, sticky="w")
        self.morse_input = tk.Text(io_frame, height=10, wrap="word", font=('Bender', 10))
        self.morse_input.grid(row=1, column=0, sticky="nsew")
        
        ttk.Label(io_frame, text=self._tr("Output:")).grid(row=0, column=1, sticky="w")
        self.morse_output = tk.Text(io_frame, height=10, wrap="word", font=('Bender', 10))
        self.morse_output.grid(row=1, column=1, sticky="nsew")
        
        # 按钮区域
        button_frame = ttk.Frame(self.text_mode_frame)
        button_frame.pack(fill="x", pady=5)
        
        ttk.Button(button_frame, text=self._tr("Encrypt"), command=self.morse_encrypt).pack(side="left", padx=5)
        ttk.Button(button_frame, text=self._tr("Decrypt"), command=self.morse_decrypt).pack(side="left", padx=5)
        ttk.Button(button_frame, text=self._tr("Play Morse"), command=self.play_morse_sound).pack(side="left", padx=5)
        ttk.Button(button_frame, text=self._tr("Clear"), command=self.clear_morse_io).pack(side="left", padx=5)
        ttk.Button(button_frame, text=self._tr("Save Audio"), command=self.save_morse_audio).pack(side="left", padx=5)
        
        # 音频模式组件 (初始隐藏)
        self.audio_mode_frame = ttk.Frame(self.morse_tab)
        
        ttk.Label(self.audio_mode_frame, text=self._tr("Audio File:")).pack(side="left")
        self.audio_file_var = tk.StringVar()
        ttk.Entry(self.audio_mode_frame, textvariable=self.audio_file_var, width=40).pack(side="left", padx=5)
        ttk.Button(self.audio_mode_frame, text=self._tr("Browse"), command=self.browse_audio_file).pack(side="left", padx=5)
        
        ttk.Button(self.audio_mode_frame, text=self._tr("Decode Audio"), command=self.decode_morse_audio).pack(side="left", padx=5)
        
        # 配置网格权重
        io_frame.grid_rowconfigure(1, weight=1)
        io_frame.grid_columnconfigure(0, weight=1)
        io_frame.grid_columnconfigure(1, weight=1)
        
        # 初始显示文本模式
        self._toggle_morse_mode()

    def _toggle_morse_mode(self):
        """切换摩斯电码模式"""
        if self.morse_mode_var.get() == "text":
            self.text_mode_frame.pack(fill="both", expand=True, padx=10, pady=5)
            self.audio_mode_frame.pack_forget()
        else:
            self.text_mode_frame.pack_forget()
            self.audio_mode_frame.pack(fill="x", padx=10, pady=5)

    def morse_encrypt(self):
        """加密文本为摩斯电码"""
        text = self.morse_input.get("1.0", tk.END).strip().upper()
        if not text:
            messagebox.showwarning(self._tr("Warning"), self._tr("Input is empty"))
            return
        
        try:
            morse_code = []
            for char in text:
                if char in self.morse_code_dict:
                    morse_code.append(self.morse_code_dict[char])
                else:
                    morse_code.append(' ')
            
            result = ' '.join(morse_code)
            self.morse_output.delete("1.0", tk.END)
            self.morse_output.insert("1.0", result)
        except Exception as e:
            messagebox.showerror(self._tr("Error"), f"{self._tr('Encryption failed')}: {str(e)}")

    def morse_decrypt(self):
        """解密摩斯电码为文本"""
        morse_code = self.morse_input.get("1.0", tk.END).strip()
        if not morse_code:
            messagebox.showwarning(self._tr("Warning"), self._tr("Input is empty"))
            return
        
        try:
            text = []
            for code in morse_code.split(' '):
                if code in self.reverse_morse_dict:
                    text.append(self.reverse_morse_dict[code])
                elif code == '':
                    text.append(' ')
                else:
                    text.append('?')
            
            result = ''.join(text)
            self.morse_output.delete("1.0", tk.END)
            self.morse_output.insert("1.0", result)
        except Exception as e:
            messagebox.showerror(self._tr("Error"), f"{self._tr('Decryption failed')}: {str(e)}")

    def play_morse_sound(self):
        """播放摩斯电码音频"""
        morse_code = self.morse_output.get("1.0", tk.END).strip()
        if not morse_code:
            messagebox.showwarning(self._tr("Warning"), self._tr("No morse code to play"))
            return
        
        try:
            # 简单实现 - 使用系统蜂鸣声
            import winsound
            for symbol in morse_code:
                if symbol == '.':
                    winsound.Beep(1000, 100)  # 短音
                elif symbol == '-':
                    winsound.Beep(1000, 300)  # 长音
                elif symbol == ' ':
                    import time
                    time.sleep(0.3)  # 字符间暂停
        except Exception as e:
            messagebox.showerror(self._tr("Error"), f"{self._tr('Failed to play sound')}: {str(e)}")

    def save_morse_audio(self):
        """保存摩斯电码为音频文件"""
        morse_code = self.morse_output.get("1.0", tk.END).strip()
        if not morse_code:
            messagebox.showwarning(self._tr("Warning"), self._tr("No morse code to save"))
            return
        
        try:
            # 尝试导入必要的库
            from pydub import AudioSegment
            from pydub.generators import Sine
        except ImportError:
            # 如果库未安装，显示更详细的安装说明
            install_msg = self._tr("Audio libraries not installed. Please install with: pip install pydub")
            messagebox.showerror(self._tr("Error"), install_msg)
            return
        
        try:
            # 创建音频片段
            dot = Sine(1000).to_audio_segment(duration=100)
            dash = Sine(1000).to_audio_segment(duration=300)
            silence = AudioSegment.silent(duration=100)
            char_silence = AudioSegment.silent(duration=300)
            
            audio = AudioSegment.empty()
            
            for symbol in morse_code:
                if symbol == '.':
                    audio += dot
                elif symbol == '-':
                    audio += dash
                elif symbol == ' ':
                    audio += char_silence
                audio += silence  # 符号间暂停
            
            # 确保Output目录存在
            output_dir = os.path.join(self.program_dir, "Output")
            os.makedirs(output_dir, exist_ok=True)
            
            # 生成默认文件名
            default_filename = f"morse_code_{datetime.now().strftime('%Y%m%d_%H%M%S')}.wav"
            default_path = os.path.join(output_dir, default_filename)
            
            # 弹出保存对话框，默认路径为Output目录
            filename = filedialog.asksaveasfilename(
                initialdir=output_dir,
                initialfile=default_filename,
                defaultextension=".wav",
                filetypes=[("WAV files", "*.wav"), ("MP3 files", "*.mp3")],
                title=self._tr("Save Morse Code Audio"))
            
            if filename:  # 用户没有取消对话框
                # 确保文件保存在Output目录下
                if not filename.startswith(output_dir):
                    filename = os.path.join(output_dir, os.path.basename(filename))
                
                audio.export(filename, format=filename.split('.')[-1])
                messagebox.showinfo(self._tr("Success"), 
                                 f"{self._tr('Audio saved successfully')}\n{filename}")
                
        except Exception as e:
            messagebox.showerror(self._tr("Error"), f"{self._tr('Failed to save audio')}: {str(e)}")

    def browse_audio_file(self):
        """浏览音频文件"""
        filename = filedialog.askopenfilename(
            filetypes=[("Audio files", "*.wav *.mp3"), ("All files", "*.*")])
        if filename:
            self.audio_file_var.set(filename)

    def decode_morse_audio(self):
        """从音频解码摩斯电码"""
        audio_file = self.audio_file_var.get()
        if not audio_file:
            messagebox.showwarning(self._tr("Warning"), self._tr("No audio file selected"))
            return
        
        try:
            from pydub import AudioSegment
            import numpy as np
            
            # 加载音频文件
            audio = AudioSegment.from_file(audio_file)
            
            # 简单实现 - 需要更复杂的算法来实际解码摩斯电码
            # 这里只是一个示例，实际解码需要更复杂的信号处理
            
            # 将音频转换为numpy数组
            samples = np.array(audio.get_array_of_samples())
            
            # 检测音频活动
            threshold = 0.1 * np.max(np.abs(samples))
            active = np.abs(samples) > threshold
            
            # 简单的摩斯电码解码
            morse_code = []
            current_symbol = ''
            last_state = False
            silent_count = 0
            
            for is_active in active[::1000]:  # 降低采样率以提高性能
                if is_active and not last_state:
                    # 开始新符号
                    if silent_count > 5:
                        morse_code.append(' ')
                    current_symbol = ''
                elif is_active:
                    current_symbol += '1'
                
                if not is_active and last_state:
                    # 符号结束
                    if len(current_symbol) > 0:
                        if len(current_symbol) < 3:
                            morse_code.append('.')
                        else:
                            morse_code.append('-')
                    current_symbol = ''
                
                last_state = is_active
                silent_count = 0 if is_active else silent_count + 1
            
            result = ''.join(morse_code)
            self.morse_output.delete("1.0", tk.END)
            self.morse_output.insert("1.0", result)
            
        except ImportError:
            messagebox.showerror(self._tr("Error"), self._tr("Audio libraries not installed"))
        except Exception as e:
            messagebox.showerror(self._tr("Error"), f"{self._tr('Failed to decode audio')}: {str(e)}")

    def clear_morse_io(self):
        """清空摩斯电码输入输出"""
        self.morse_input.delete("1.0", tk.END)
        self.morse_output.delete("1.0", tk.END)

    def _load_default_chinese(self):
        """默认中文语言包"""
        return {
            "Caesar Cipher": "凯撒加解密",
            "Settings": "程序设置",
            "Character Set": "字符集",
            "Punctuation": "标点符号",
            "Custom": "自定义",
            "Custom Mapping": "自定义映射",
            "Edit Mapping": "编辑映射",
            "Dynamic Shift": "逐字偏移",
            "Step": "步长",
            "Operation": "操作设置",
            "Encrypt": "加密",
            "Decrypt": "解密",
            "Shift": "位移量",
            "Input": "输入",
            "Output": "输出",
            "Execute": "执行",
            "Save Result": "保存结果",
            "History": "历史记录",
            "Clear": "清空",
            "Language Settings": "语言设置",
            "Language": "语言",
            "Program Information": "程序信息",
            "Version": "版本",
            "Author": "作者",
            "This program is still under development and testing": "本程序仍在改进测试中",
            "Import Language Pack": "导入语言包",
            "Apply Settings": "应用设置",
            "Warning": "警告",
            "Success": "成功",
            "Error": "错误",
            "Input is empty": "输入内容为空",
            "No mapping selected": "未选择映射",
            "No character set selected": "未选择字符集",
            "No result to save": "没有可保存的结果",
            "Result saved successfully": "结果保存成功",
            "Failed to save file": "保存文件失败",
            "No history records": "没有历史记录",
            "Time": "时间",
            "Algorithm": "算法",
            "Mode": "模式",
            "Mapping saved successfully": "映射保存成功",
            "Failed to load mappings": "加载映射失败",
            "Failed to save mappings": "保存映射失败",
            "Language pack imported successfully": "语言包导入成功",
            "Invalid language pack format": "无效的语言包格式",
            "Failed to load language pack": "加载语言包失败",
            "Failed to save history": "保存历史记录失败",
            "Failed to load history": "加载历史记录失败",
            "Failed to save settings": "保存设置失败",
            "Language changed. Please restart the program for full effect.": "语言已更改，请重启程序使更改完全生效",
            "Please enter a mapping name": "请输入映射名称",
            "Each mapping should be single character": "每个映射应为单个字符",
            "No valid mappings to save": "没有有效的映射可保存",
            "Generate Random Mapping": "随机生成映射",
            "File Embed Tool": "文件嵌入工具",
            "File Selection": "文件选择",
            "Outer File": "表文件:",
            "Inner File": "里文件:",
            "Mutation Parameters": "异变参数 (可选)",
            "Show Mutation Parameters": "显示异变参数",
            "Mutation Key": "异变密钥:",
            "Generate Random Key": "生成随机密钥",
            "Create Chimera File": "创建奇美拉文件",
            "Clear Selection": "清空选择",
            "File Extraction": "文件拆解",
            "Select Chimera File": "选择奇美拉文件",
            "Chimera File": "奇美拉文件:",
            "Mutation Parameters (if used)": "异变参数 (如加密时使用过)",
            "Extract Files": "拆解文件",
            "Error": "错误",
            "Please select both outer and inner files": "请同时选择表文件和里文件",
            "Chimera file created successfully": "奇美拉文件创建成功!",
            "Failed to create chimera file": "创建奇美拉文件失败",
            "Please select chimera file": "请选择奇美拉文件",
            "Invalid chimera file format": "无效的奇美拉文件格式",
            "This file uses mutation parameters, please enter the correct mutation key": "此文件使用了异变参数，请输入正确的异变密钥",
            "Decryption failed": "解密失败",
            "Files extracted successfully": "文件拆解成功!",
            "Failed to extract files": "拆解文件失败",
            "Morse Code": "摩斯电码",
            "Operation Mode": "操作模式",
            "Text Mode": "文本模式",
            "Audio Mode": "音频模式",
            "Encrypt": "加密",
            "Decrypt": "解密",
            "Play Morse": "播放摩斯",
            "Save Audio": "保存音频",
            "Audio File": "音频文件:",
            "Browse": "浏览",
            "Decode Audio": "解码音频",
            "No morse code to play": "没有可播放的摩斯电码",
            "Audio saved successfully": "音频保存成功",
            "Audio libraries not installed": "音频库未安装",
            "Failed to save audio": "保存音频失败",
            "No audio file selected": "未选择音频文件",
            "Failed to decode audio": "解码音频失败"
        }

    def _load_default_english(self):
        """默认英文语言包"""
        return {
            "Caesar Cipher": "Caesar Cipher",
            "Settings": "Settings",
            "Character Set": "Character Set",
            "Punctuation": "Punctuation",
            "Custom": "Custom",
            "Custom Mapping": "Custom Mapping",
            "Edit Mapping": "Edit Mapping",
            "Dynamic Shift": "Dynamic Shift",
            "Step": "Step",
            "Operation": "Operation",
            "Encrypt": "Encrypt",
            "Decrypt": "Decrypt",
            "Shift": "Shift",
            "Input": "Input",
            "Output": "Output",
            "Execute": "Execute",
            "Save Result": "Save Result",
            "History": "History",
            "Clear": "Clear",
            "Language Settings": "Language Settings",
            "Language": "Language",
            "Program Information": "Program Information",
            "Version": "Version",
            "Author": "Author",
            "This program is still under development and testing": "This program is still under development and testing",
            "Import Language Pack": "Import Language Pack",
            "Apply Settings": "Apply Settings",
            "Warning": "Warning",
            "Success": "Success",
            "Error": "Error",
            "Input is empty": "Input is empty",
            "No mapping selected": "No mapping selected",
            "No character set selected": "No character set selected",
            "No result to save": "No result to save",
            "Result saved successfully": "Result saved successfully",
            "Failed to save file": "Failed to save file",
            "No history records": "No history records",
            "Time": "Time",
            "Algorithm": "Algorithm",
            "Mode": "Mode",
            "Mapping saved successfully": "Mapping saved successfully",
            "Failed to load mappings": "Failed to load mappings",
            "Failed to save mappings": "Failed to save mappings",
            "Language pack imported successfully": "Language pack imported successfully",
            "Invalid language pack format": "Invalid language pack format",
            "Failed to load language pack": "Failed to load language pack",
            "Failed to save history": "Failed to save history",
            "Failed to load history": "Failed to load history",
            "Failed to save settings": "Failed to save settings",
            "Language changed. Please restart the program for full effect.": "Language changed. Please restart the program for full effect.",
            "Please enter a mapping name": "Please enter a mapping name",
            "Each mapping should be single character": "Each mapping should be single character",
            "No valid mappings to save": "No valid mappings to save",
            "Generate Random Mapping": "Generate Random Mapping",
            "File Embed Tool": "File Embed Tool",
            "File Selection": "File Selection",
            "Outer File": "Outer File:",
            "Inner File": "Inner File:",
            "Mutation Parameters": "Mutation Parameters (optional)",
            "Show Mutation Parameters": "Show Mutation Parameters",
            "Mutation Key": "Mutation Key:",
            "Generate Random Key": "Generate Random Key",
            "Create Chimera File": "Create Chimera File",
            "Clear Selection": "Clear Selection",
            "File Extraction": "File Extraction",
            "Select Chimera File": "Select Chimera File",
            "Chimera File": "Chimera File:",
            "Mutation Parameters (if used)": "Mutation Parameters (if used)",
            "Extract Files": "Extract Files",
            "Error": "Error",
            "Please select both outer and inner files": "Please select both outer and inner files",
            "Chimera file created successfully": "Chimera file created successfully!",
            "Failed to create chimera file": "Failed to create chimera file",
            "Please select chimera file": "Please select chimera file",
            "Invalid chimera file format": "Invalid chimera file format",
            "This file uses mutation parameters, please enter the correct mutation key": "This file uses mutation parameters, please enter the correct mutation key",
            "Decryption failed": "Decryption failed",
            "Files extracted successfully": "Files extracted successfully!",
            "Failed to extract files": "Failed to extract files",
            "Morse Code": "Morse Code",
            "Operation Mode": "Operation Mode",
            "Text Mode": "Text Mode",
            "Audio Mode": "Audio Mode",
            "Encrypt": "Encrypt",
            "Decrypt": "Decrypt",
            "Play Morse": "Play Morse",
            "Save Audio": "Save Audio",
            "Audio File": "Audio File:",
            "Browse": "Browse",
            "Decode Audio": "Decode Audio",
            "No morse code to play": "No morse code to play",
            "Audio saved successfully": "Audio saved successfully",
            "Audio libraries not installed": "Audio libraries not installed",
            "Failed to save audio": "Failed to save audio",
            "No audio file selected": "No audio file selected",
            "Failed to decode audio": "Failed to decode audio"
        }
        
    def _init_history_file(self):
        """初始化历史记录文件"""
        history_path = os.path.join(self.program_dir, "History.txt")
        if not os.path.exists(history_path):
            with open(history_path, 'w', encoding='utf-8') as f:
                f.write("=== Sakana Toolkit History ===\n\n")

    def _tr(self, key):
        """翻译函数"""
        return self.language_packs[self.current_language].get(key, key)

    def _detect_system_language(self):
        """检测系统默认语言"""
        try:
            sys_lang = locale.getdefaultlocale()[0]
            return "zh_CN" if sys_lang and 'zh' in sys_lang.lower() else "en_US"
        except:
            return "en_US"

    def _init_program_directory(self):
        """初始化程序目录结构"""
        # 获取程序所在目录
        if getattr(sys, 'frozen', False):
            self.program_dir = os.path.dirname(sys.executable)
        else:
            self.program_dir = os.path.dirname(os.path.abspath(__file__))
        
        # 检查是否在根目录或桌面
        if (os.path.splitdrive(self.program_dir)[1] in ('\\', '') or 
            os.path.basename(self.program_dir).lower() == 'desktop'):
            messagebox.showwarning(
                "Warning",
                "不建议在根目录或桌面运行程序\n请创建专用文件夹"
            )
        
        # 创建必要目录
        os.makedirs(os.path.join(self.program_dir, "localization"), exist_ok=True)
        
        # 初始化默认文件
        if not os.path.exists(os.path.join(self.program_dir, "settings.json")):
            with open(os.path.join(self.program_dir, "settings.json"), 'w', encoding='utf-8') as f:
                json.dump({
                    "language": self.current_language,
                    "window_size": "1280x720",  # 更新默认尺寸
                    "show_startup_hint": False
                }, f)

    def load_custom_mappings(self):
        """加载自定义映射"""
        try:
            mapping_file = os.path.join(self.program_dir, "custom_mappings.json")
            if os.path.exists(mapping_file):
                with open(mapping_file, 'r', encoding='utf-8') as f:
                    self.custom_mappings = json.load(f)
        except Exception as e:
            print(f"加载映射失败: {str(e)}")
            self.custom_mappings = {}

    def _load_settings(self):
        """加载程序设置"""
        try:
            with open(os.path.join(self.program_dir, "settings.json"), 'r', encoding='utf-8') as f:
                settings = json.load(f)
                # 确保有窗口尺寸设置
                if "window_size" not in settings:
                    settings["window_size"] = "1280x720"
                return settings
        except:
            return {
                "language": self.current_language,
                "window_size": "1280x720",  # 默认尺寸
                "show_startup_hint": False
            }

    def _load_localization_files(self):
        """加载额外的本地化文件（合并到现有语言包）"""
        loc_dir = os.path.join(self.program_dir, "localization")
        if os.path.exists(loc_dir):
            for file in os.listdir(loc_dir):
                if file.endswith('.json'):
                    lang = os.path.splitext(file)[0]
                    try:
                        with open(os.path.join(loc_dir, file), 'r', encoding='utf-8') as f:
                            # 合并而不是覆盖现有语言包
                            if lang in self.language_packs:
                                self.language_packs[lang].update(json.load(f))
                            else:
                                self.language_packs[lang] = json.load(f)
                    except Exception as e:
                        print(f"加载本地化文件 {file} 失败: {str(e)}")

    def _setup_caesar_tab(self):
        """凯撒密码标签页"""
        self.caesar_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.caesar_tab, text=self._tr("Caesar Cipher"))

        # 调整框架的内边距
        charset_frame = ttk.LabelFrame(self.caesar_tab, text=self._tr("Character Set"))
        charset_frame.pack(fill="x", padx=15, pady=10)  # 增加内边距
        
        # 字符集选择
        charset_frame = ttk.LabelFrame(self.caesar_tab, text=self._tr("Character Set"))
        charset_frame.pack(fill="x", padx=10, pady=5)
        
        self.charset_vars = {
            "lower": tk.BooleanVar(value=True),
            "upper": tk.BooleanVar(value=True),
            "digits": tk.BooleanVar(value=True),
            "punctuation": tk.BooleanVar(value=False),
            "custom": tk.BooleanVar(value=False),
            "custom_mapping": tk.BooleanVar(value=False),
            "dynamic_shift": tk.BooleanVar(value=False)
        }
        
        ttk.Checkbutton(charset_frame, text="a-z", variable=self.charset_vars["lower"]).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(charset_frame, text="A-Z", variable=self.charset_vars["upper"]).grid(row=0, column=1, sticky="w")
        ttk.Checkbutton(charset_frame, text="0-9", variable=self.charset_vars["digits"]).grid(row=0, column=2, sticky="w")
        ttk.Checkbutton(charset_frame, text=self._tr("Punctuation"), variable=self.charset_vars["punctuation"]).grid(row=0, column=3, sticky="w")
        ttk.Checkbutton(charset_frame, text=self._tr("Custom"), variable=self.charset_vars["custom"]).grid(row=0, column=4, sticky="w")
        ttk.Checkbutton(charset_frame, text=self._tr("Custom Mapping"), variable=self.charset_vars["custom_mapping"]).grid(row=0, column=5, sticky="w")
        
        self.custom_charset = tk.StringVar()
        ttk.Entry(charset_frame, textvariable=self.custom_charset, width=30).grid(row=1, column=0, columnspan=5, sticky="ew")
        ttk.Button(charset_frame, text=self._tr("Edit Mapping"), command=self.edit_custom_mapping).grid(row=1, column=5, sticky="e")
        
        # 操作设置
        operation_frame = ttk.LabelFrame(self.caesar_tab, text=self._tr("Operation"))
        operation_frame.pack(fill="x", padx=10, pady=5)
        
        self.mode_var = tk.StringVar(value="encrypt")
        ttk.Radiobutton(operation_frame, text=self._tr("Encrypt"), variable=self.mode_var, value="encrypt").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(operation_frame, text=self._tr("Decrypt"), variable=self.mode_var, value="decrypt").grid(row=0, column=1, sticky="w")
        
        ttk.Label(operation_frame, text=self._tr("Shift:")).grid(row=1, column=0, sticky="w")
        self.shift_var = tk.IntVar(value=3)
        ttk.Spinbox(operation_frame, from_=1, to=25, textvariable=self.shift_var, width=5).grid(row=1, column=1, sticky="w")
        
        # 逐字偏移设置
        ttk.Checkbutton(operation_frame, text=self._tr("Dynamic Shift"), variable=self.charset_vars["dynamic_shift"]).grid(row=2, column=0, sticky="w")
        
        self.dynamic_shift_frame = ttk.Frame(operation_frame)
        self.dynamic_shift_frame.grid(row=2, column=1, sticky="w")
        
        ttk.Label(self.dynamic_shift_frame, text=self._tr("Step:")).pack(side="left")
        self.dynamic_step_var = tk.IntVar(value=1)
        ttk.Spinbox(self.dynamic_shift_frame, from_=1, to=10, textvariable=self.dynamic_step_var, width=3).pack(side="left", padx=5)
        
        self.dynamic_direction_var = tk.StringVar(value="right")
        ttk.Radiobutton(self.dynamic_shift_frame, text="→", variable=self.dynamic_direction_var, value="right").pack(side="left")
        ttk.Radiobutton(self.dynamic_shift_frame, text="←", variable=self.dynamic_direction_var, value="left").pack(side="left")
        
        # 输入输出
        io_frame = ttk.Frame(self.caesar_tab)
        io_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        ttk.Label(io_frame, text=self._tr("Input:")).grid(row=0, column=0, sticky="w")
        self.input_text = tk.Text(io_frame, height=10, wrap="word", font=('Bender', 10))
        self.input_text.grid(row=1, column=0, sticky="nsew")
        
        ttk.Label(io_frame, text=self._tr("Output:")).grid(row=0, column=1, sticky="w")
        self.output_text = tk.Text(io_frame, height=10, wrap="word", font=('Bender', 10))
        self.output_text.grid(row=1, column=1, sticky="nsew")
        
        # 按钮区域
        button_frame = ttk.Frame(self.caesar_tab)
        button_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(button_frame, text=self._tr("Execute"), command=self.execute_caesar).pack(side="left", padx=5)
        ttk.Button(button_frame, text=self._tr("Save Result"), command=self.save_result).pack(side="left", padx=5)
        ttk.Button(button_frame, text=self._tr("History"), command=self.show_history).pack(side="left", padx=5)
        ttk.Button(button_frame, text=self._tr("Clear"), command=self.clear_io).pack(side="left", padx=5)
        
        # 配置网格权重
        io_frame.grid_rowconfigure(1, weight=1)
        io_frame.grid_columnconfigure(0, weight=1)
        io_frame.grid_columnconfigure(1, weight=1)

    def _setup_settings_tab(self):
        """设置标签页"""
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text=self._tr("Settings"), sticky="nsew")
        
        # 程序信息框
        info_frame = ttk.LabelFrame(self.settings_tab, text=self._tr("Program Information"))
        info_frame.pack(fill="x", padx=10, pady=5)
    
        ttk.Label(info_frame, text=f"{self._tr('Version')}: {self.version}").pack(anchor="w")
        ttk.Label(info_frame, text=f"{self._tr('Author')}: {self.author}").pack(anchor="w")
        ttk.Label(info_frame, text=self._tr("This program is still under development and testing"), 
                foreground="orange").pack(anchor="w", pady=5)
    
        # 语言设置
        lang_frame = ttk.LabelFrame(self.settings_tab, text=self._tr("Language Settings"))
        lang_frame.pack(fill="x", padx=10, pady=5)
    
        ttk.Label(lang_frame, text=self._tr("Language:")).grid(row=0, column=0, sticky="w")
        self.lang_var = tk.StringVar(value=self.settings.get("language", self.current_language))
        lang_menu = ttk.OptionMenu(lang_frame, self.lang_var, 
                                 self.current_language, 
                                 *sorted(self.language_packs.keys()))
        lang_menu.grid(row=0, column=1, sticky="ew")
    
        ttk.Button(lang_frame, text=self._tr("Import Language Pack"),
                 command=self.import_language_pack).grid(row=1, column=0, columnspan=2, pady=5)
    
        # 应用按钮
        ttk.Button(self.settings_tab, text=self._tr("Apply Settings"),
                 command=self.apply_settings).pack(pady=10)

        # 创建摩斯电码标签页
        self._setup_morse_tab()

    def _setup_file_embed_tab(self):
        """文件嵌入工具标签页"""
        self.file_embed_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.file_embed_tab, text=self._tr("File Embed Tool"))
        
        # 创建标签页
        self.file_embed_notebook = ttk.Notebook(self.file_embed_tab)
        self.file_embed_notebook.pack(fill="both", expand=True)
        
        # 创建文件嵌入标签页
        self._create_embed_tab()
        
        # 创建文件拆解标签页
        self._create_extract_tab()
    
    def _create_embed_tab(self):
        """创建文件嵌入标签页"""
        embed_tab = ttk.Frame(self.file_embed_notebook)
        self.file_embed_notebook.add(embed_tab, text=self._tr("File Embed"))
        
        # 文件选择区域
        file_frame = ttk.LabelFrame(embed_tab, text=self._tr("File Selection"))
        file_frame.pack(fill="x", padx=5, pady=5)
        
        # 表文件选择
        ttk.Label(file_frame, text=self._tr("Outer File")).grid(row=0, column=0, sticky="w")
        self.outer_file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.outer_file_var, width=40).grid(row=0, column=1, padx=5)
        ttk.Button(file_frame, text="...", command=self._browse_outer_file).grid(row=0, column=2)
        
        # 里文件选择
        ttk.Label(file_frame, text=self._tr("Inner File")).grid(row=1, column=0, sticky="w")
        self.inner_file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.inner_file_var, width=40).grid(row=1, column=1, padx=5)
        ttk.Button(file_frame, text="...", command=self._browse_inner_file).grid(row=1, column=2)
        
        # 异变参数设置
        self.mutation_frame = ttk.LabelFrame(embed_tab, text=self._tr("Mutation Parameters"))
        self.mutation_frame.pack(fill="x", padx=5, pady=5)
        
        # 显示/隐藏复选框
        self.show_key_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.mutation_frame, text=self._tr("Show Mutation Parameters"), 
                       variable=self.show_key_var, 
                       command=self.toggle_key_visibility).grid(row=0, column=0, sticky="w", columnspan=3)
        
        ttk.Label(self.mutation_frame, text=self._tr("Mutation Key")).grid(row=1, column=0, sticky="w")
        self.mutation_key_var = tk.StringVar()
        self.key_entry = ttk.Entry(self.mutation_frame, textvariable=self.mutation_key_var, 
                                 show="*", width=30)
        self.key_entry.grid(row=1, column=1, sticky="w")
        
        ttk.Button(self.mutation_frame, text=self._tr("Generate Random Key"), 
                  command=self._generate_random_key).grid(row=1, column=2, padx=5)
        
        # 操作按钮
        button_frame = ttk.Frame(embed_tab)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text=self._tr("Create Chimera File"), command=self.create_chimera).pack(side="left", padx=5)
        ttk.Button(button_frame, text=self._tr("Clear Selection"), command=self.clear_files).pack(side="left", padx=5)
        
        # 状态显示
        self.status_var = tk.StringVar()
        ttk.Label(embed_tab, textvariable=self.status_var).pack(pady=5)
        
    def _create_extract_tab(self):
        """创建文件拆解标签页"""
        extract_tab = ttk.Frame(self.file_embed_notebook)
        self.file_embed_notebook.add(extract_tab, text=self._tr("File Extraction"))
        
        # 文件选择区域
        file_frame = ttk.LabelFrame(extract_tab, text=self._tr("Select Chimera File"))
        file_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(file_frame, text=self._tr("Chimera File")).grid(row=0, column=0, sticky="w")
        self.chimera_file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.chimera_file_var, width=40).grid(row=0, column=1, padx=5)
        ttk.Button(file_frame, text="...", command=self._browse_chimera_file).grid(row=0, column=2)
        
        # 异变参数设置
        self.extract_mutation_frame = ttk.LabelFrame(extract_tab, text=self._tr("Mutation Parameters (if used)"))
        self.extract_mutation_frame.pack(fill="x", padx=5, pady=5)
        
        # 显示/隐藏复选框
        self.extract_show_key_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.extract_mutation_frame, text=self._tr("Show Mutation Parameters"), 
                       variable=self.extract_show_key_var, 
                       command=self.toggle_extract_key_visibility).grid(row=0, column=0, sticky="w", columnspan=3)
        
        ttk.Label(self.extract_mutation_frame, text=self._tr("Mutation Key")).grid(row=1, column=0, sticky="w")
        self.extract_key_var = tk.StringVar()
        self.extract_key_entry = ttk.Entry(self.extract_mutation_frame, 
                                         textvariable=self.extract_key_var, 
                                         show="*", width=30)
        self.extract_key_entry.grid(row=1, column=1, sticky="w")
        
        # 操作按钮
        button_frame = ttk.Frame(extract_tab)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text=self._tr("Extract Files"), command=self.extract_files).pack(side="left", padx=5)
        
        # 状态显示
        self.extract_status_var = tk.StringVar()
        ttk.Label(extract_tab, textvariable=self.extract_status_var).pack(pady=5)
        
    def toggle_key_visibility(self):
        """切换密钥可见性"""
        show = self.show_key_var.get()
        self.key_entry.config(show="" if show else "*")
        
    def toggle_extract_key_visibility(self):
        """切换拆解密钥可见性"""
        show = self.extract_show_key_var.get()
        self.extract_key_entry.config(show="" if show else "*")
        
    def _browse_outer_file(self):
        """选择表文件"""
        filename = filedialog.askopenfilename(title=self._tr("Select Outer File"))
        if filename:
            self.outer_file_var.set(filename)
            self.status_var.set(f"{self._tr('Outer File')}: {os.path.basename(filename)}")
            
    def _browse_inner_file(self):
        """选择里文件"""
        filename = filedialog.askopenfilename(title=self._tr("Select Inner File"))
        if filename:
            self.inner_file_var.set(filename)
            self.status_var.set(f"{self._tr('Inner File')}: {os.path.basename(filename)}")
            
    def _browse_chimera_file(self):
        """选择奇美拉文件"""
        filename = filedialog.askopenfilename(title=self._tr("Select Chimera File"))
        if filename:
            self.chimera_file_var.set(filename)
            self.extract_status_var.set(f"{self._tr('Chimera File')}: {os.path.basename(filename)}")
            
    def _generate_random_key(self):
        """生成随机异变密钥"""
        key = secrets.token_hex(16)
        self.mutation_key_var.set(key)
        self.status_var.set(self._tr("Random mutation key generated"))
            
    def clear_files(self):
        """清空已选文件"""
        self.outer_file_var.set("")
        self.inner_file_var.set("")
        self.mutation_key_var.set("")
        self.status_var.set(self._tr("Selection cleared"))
        
    def create_chimera(self):
        """创建奇美拉文件"""
        outer_file = self.outer_file_var.get()
        inner_file = self.inner_file_var.get()
        
        if not outer_file or not inner_file:
            messagebox.showerror(self._tr("Error"), self._tr("Please select both outer and inner files"))
            return
            
        try:
            # 读取两个文件
            with open(outer_file, 'rb') as f:
                outer_data = f.read()
                outer_name = os.path.basename(outer_file)
                
            with open(inner_file, 'rb') as f:
                inner_data = f.read()
                inner_name = os.path.basename(inner_file)
                
            # 获取异变密钥
            mutation_key = self.mutation_key_var.get().encode('utf-8') if self.mutation_key_var.get() else None
            
            # 如果提供了异变密钥，则加密文件数据
            if mutation_key:
                outer_data = self._mutate_data(outer_data, mutation_key)
                inner_data = self._mutate_data(inner_data, mutation_key)
                
            # 创建输出文件名
            output_file = filedialog.asksaveasfilename(
                defaultextension=".chimera",
                filetypes=[(self._tr("Chimera files"), "*.chimera"), (self._tr("All files"), "*.*")],
                title=self._tr("Save Chimera File")
            )
            
            if not output_file:
                return  # 用户取消
                
            # 创建奇美拉文件
            self._create_chimera_file(
                output_file, 
                outer_data, inner_data,
                outer_name, inner_name,
                bool(mutation_key)
            )
            
            self.status_var.set(f"{self._tr('Chimera file created successfully')}: {os.path.basename(output_file)}")
            messagebox.showinfo(self._tr("Success"), self._tr("Chimera file created successfully"))
            
        except Exception as e:
            messagebox.showerror(self._tr("Error"), f"{self._tr('Failed to create chimera file')}: {str(e)}")
            self.status_var.set(self._tr("Failed to create chimera file"))
            
    def _mutate_data(self, data, key):
        """使用异变密钥加密数据"""
        # 使用SHA256哈希密钥生成AES密钥
        aes_key = hashlib.sha256(key).digest()[:32]
        cipher = AES.new(aes_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        return cipher.iv + ct_bytes
        
    def _create_chimera_file(self, output_path, outer_data, inner_data, outer_name, inner_name, mutated):
        """
        创建奇美拉文件格式:
        - 8字节: 魔数 'CHIMERA\x00'
        - 1字节: 版本号 (当前为2)
        - 1字节: 是否使用异变 (0或1)
        - 2字节: 表文件名长度 (N)
        - N字节: 表文件名
        - 2字节: 里文件名长度 (M)
        - M字节: 里文件名
        - 8字节: 表文件大小
        - 8字节: 里文件大小
        - 表文件数据
        - 里文件数据
        """
        with open(output_path, 'wb') as f:
            # 写入文件头
            f.write(b'CHIMERA\x00')  # 魔数
            f.write(bytes([2]))     # 版本号
            f.write(bytes([1 if mutated else 0]))  # 异变标志
            
            # 写入文件名
            outer_name_bytes = outer_name.encode('utf-8')
            inner_name_bytes = inner_name.encode('utf-8')
            
            f.write(len(outer_name_bytes).to_bytes(2, 'little'))  # 表文件名长度
            f.write(outer_name_bytes)  # 表文件名
            
            f.write(len(inner_name_bytes).to_bytes(2, 'little'))  # 里文件名长度
            f.write(inner_name_bytes)  # 里文件名
            
            # 写入文件大小
            f.write(len(outer_data).to_bytes(8, 'little'))  # 表文件大小
            f.write(len(inner_data).to_bytes(8, 'little'))  # 里文件大小
            
            # 写入文件数据
            f.write(outer_data)
            f.write(inner_data)
            
    def extract_files(self):
        """拆解奇美拉文件"""
        chimera_file = self.chimera_file_var.get()
        if not chimera_file:
            messagebox.showerror(self._tr("Error"), self._tr("Please select chimera file"))
            return
            
        try:
            # 读取奇美拉文件
            with open(chimera_file, 'rb') as f:
                header = f.read(8)
                if header != b'CHIMERA\x00':
                    raise ValueError(self._tr("Invalid chimera file format"))
                    
                version = int.from_bytes(f.read(1), 'little')
                mutated = bool(int.from_bytes(f.read(1), 'little'))
                
                # 读取文件名
                outer_name_len = int.from_bytes(f.read(2), 'little')
                outer_name = f.read(outer_name_len).decode('utf-8')
                
                inner_name_len = int.from_bytes(f.read(2), 'little')
                inner_name = f.read(inner_name_len).decode('utf-8')
                
                # 读取文件大小
                outer_size = int.from_bytes(f.read(8), 'little')
                inner_size = int.from_bytes(f.read(8), 'little')
                
                # 读取文件数据
                outer_data = f.read(outer_size)
                inner_data = f.read(inner_size)
                
            # 如果文件使用了异变参数，需要解密
            if mutated:
                mutation_key = self.extract_key_var.get().encode('utf-8') if self.extract_key_var.get() else None
                if not mutation_key:
                    messagebox.showerror(self._tr("Error"), 
                                       self._tr("This file uses mutation parameters, please enter the correct mutation key"))
                    return
                    
                try:
                    outer_data = self._demutate_data(outer_data, mutation_key)
                    inner_data = self._demutate_data(inner_data, mutation_key)
                except Exception as e:
                    messagebox.showerror(self._tr("Error"), 
                                       f"{self._tr('Decryption failed')}: {str(e)}\n{self._tr('May be incorrect mutation key')}")
                    return
                    
            # 创建输出目录
            output_dir = os.path.join(self.program_dir, "Output")
            os.makedirs(output_dir, exist_ok=True)
            
            # 保存表文件
            outer_path = os.path.join(output_dir, outer_name)
            with open(outer_path, 'wb') as f:
                f.write(outer_data)
                
            # 保存里文件
            inner_path = os.path.join(output_dir, inner_name)
            with open(inner_path, 'wb') as f:
                f.write(inner_data)
                
            self.extract_status_var.set(f"{self._tr('Files extracted successfully, saved in')}: {output_dir}")
            messagebox.showinfo(self._tr("Success"), 
                              f"{self._tr('Files extracted successfully')}!\n{self._tr('Outer File')}: {outer_name}\n{self._tr('Inner File')}: {inner_name}")
            
        except Exception as e:
            messagebox.showerror(self._tr("Error"), 
                               f"{self._tr('Failed to extract files')}: {str(e)}")
            self.extract_status_var.set(self._tr("Failed to extract files"))
            
    def _demutate_data(self, data, key):
        """使用异变密钥解密数据"""
        # 分离IV和加密数据
        iv = data[:16]
        ct = data[16:]
        
        # 使用SHA256哈希密钥生成AES密钥
        aes_key = hashlib.sha256(key).digest()[:32]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt

    def execute_caesar(self):
        """执行凯撒加密/解密"""
        input_text = self.input_text.get("1.0", tk.END).strip()
        if not input_text:
            messagebox.showwarning(self._tr("Warning"), self._tr("Input is empty"))
            return
        
        # 检查是否使用自定义映射
        use_mapping = self.charset_vars["custom_mapping"].get()
        mapping_name = self.custom_charset.get()
        
        if use_mapping and mapping_name not in self.custom_mappings:
            messagebox.showwarning(self._tr("Warning"), self._tr("No mapping selected"))
            return
        
        # 检查是否使用逐字偏移
        dynamic_shift = self.charset_vars["dynamic_shift"].get()
        step = self.dynamic_step_var.get()
        direction = self.dynamic_direction_var.get()
        
        # 构建字符集或获取映射
        if use_mapping:
            charset = list(self.custom_mappings[mapping_name].keys())
            mapping = self.custom_mappings[mapping_name]
        else:
            charset = self._build_charset()
            if not charset:
                return
            mapping = None
        
        shift = self.shift_var.get()
        mode = self.mode_var.get()
        
        # 执行加密/解密
        result = []
        current_charset = list(charset)  # 创建字符集的副本用于动态偏移
        
        for char in input_text:
            if char in current_charset:
                if use_mapping:
                    # 使用自定义映射
                    mapped_char = mapping[char]
                    pos = current_charset.index(mapped_char)
                else:
                    pos = current_charset.index(char)
                
                if mode == "encrypt":
                    new_pos = (pos + shift) % len(current_charset)
                else:
                    new_pos = (pos - shift) % len(current_charset)
                
                result.append(current_charset[new_pos])
                
                # 如果启用逐字偏移，则调整字符集
                if dynamic_shift:
                    if direction == "right":
                        current_charset = current_charset[-step:] + current_charset[:-step]
                    else:
                        current_charset = current_charset[step:] + current_charset[:step]
            else:
                result.append(char)
        
        output_text = "".join(result)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", output_text)
        
        # 记录历史
        history_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "algorithm": "Caesar" + (" (Custom Mapping)" if use_mapping else "") + 
                        (" (Dynamic Shift)" if dynamic_shift else ""),
            "mode": mode,
            "shift": shift,
            "dynamic_shift": {
                "enabled": dynamic_shift,
                "step": step if dynamic_shift else None,
                "direction": direction if dynamic_shift else None
            },
            "mapping": mapping_name if use_mapping else None,
            "input": input_text,
            "output": output_text,
            "charset": charset if not use_mapping else None
        }
        
        self.history.append(history_entry)
        self._save_history_entry(history_entry)

    def _save_history_entry(self, entry):
        """保存历史记录条目到文件"""
        history_path = os.path.join(self.program_dir, "History.txt")
        try:
            with open(history_path, 'a', encoding='utf-8') as f:
                f.write(f"Time: {entry['timestamp']}\n")
                f.write(f"Algorithm: {entry['algorithm']}\n")
                f.write(f"Mode: {entry['mode']}, Shift: {entry['shift']}")
                if entry['dynamic_shift']['enabled']:
                    f.write(f", Dynamic Shift: {entry['dynamic_shift']['step']} steps {entry['dynamic_shift']['direction']}")
                if entry['mapping']:
                    f.write(f", Mapping: {entry['mapping']}")
                f.write("\n")
                f.write(f"Input:\n{entry['input']}\n")
                f.write(f"Output:\n{entry['output']}\n")
                f.write("-" * 50 + "\n\n")
        except Exception as e:
            messagebox.showerror(self._tr("Error"), f"{self._tr('Failed to save history')}: {str(e)}")

    def _build_charset(self):
        """构建字符集"""
        charset = ""
        if self.charset_vars["lower"].get():
            charset += "abcdefghijklmnopqrstuvwxyz"
        if self.charset_vars["upper"].get():
            charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if self.charset_vars["digits"].get():
            charset += "0123456789"
        if self.charset_vars["punctuation"].get():
            charset += "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
        if self.charset_vars["custom"].get():
            charset += self.custom_charset.get()
        
        if not charset:
            messagebox.showwarning(self._tr("Warning"), self._tr("No character set selected"))
            return None
        
        return charset

    def edit_custom_mapping(self):
        """改进后的自定义字符映射编辑功能"""
        mapping_window = tk.Toplevel(self.root)
        mapping_window.title(self._tr("Custom Character Mapping"))
        mapping_window.geometry("650x450")
        
        # 主框架
        main_frame = ttk.Frame(mapping_window)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # 映射名称
        name_frame = ttk.Frame(main_frame)
        name_frame.pack(fill="x", pady=5)
        
        ttk.Label(name_frame, text=self._tr("Mapping Name:")).pack(side="left")
        name_var = tk.StringVar(value="new_mapping")
        name_entry = ttk.Entry(name_frame, textvariable=name_var)
        name_entry.pack(side="left", fill="x", expand=True, padx=5)
        
        # 映射表格
        table_frame = ttk.Frame(main_frame)
        table_frame.pack(fill="both", expand=True)
        
        # 创建滚动区域
        scrollbar = ttk.Scrollbar(table_frame)
        scrollbar.pack(side="right", fill="y")
        
        # 使用Text部件代替Canvas来实现滚动
        text_widget = tk.Text(table_frame, yscrollcommand=scrollbar.set, wrap="none")
        text_widget.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=text_widget.yview)
        
        # 在Text部件中嵌入Frame
        scrollable_frame = ttk.Frame(text_widget)
        text_widget.window_create("1.0", window=scrollable_frame)
        
        # 动态添加映射行
        self.mapping_entries = []
        
        # 初始添加5行空白映射
        for _ in range(5):
            self._add_mapping_row(scrollable_frame)
        
        # 按钮区域
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x", pady=5)
        
        # 按钮框架
        left_button_frame = ttk.Frame(button_frame)
        left_button_frame.pack(side="left", fill="x", expand=True)
        
        right_button_frame = ttk.Frame(button_frame)
        right_button_frame.pack(side="right", fill="x", expand=True)
        
        # 添加按钮
        ttk.Button(
            left_button_frame, 
            text=self._tr("Add New Pair"), 
            command=lambda: self._add_mapping_row(scrollable_frame)
        ).pack(side="left", padx=5)
        
        ttk.Button(
            left_button_frame,
            text=self._tr("Load Mapping"),
            command=lambda: self._load_existing_mapping(name_var, scrollable_frame)
        ).pack(side="left", padx=5)
        
        ttk.Button(
            left_button_frame,
            text=self._tr("Generate Random Mapping"),
            command=lambda: self._generate_random_mapping(scrollable_frame)
        ).pack(side="left", padx=5)
        
        ttk.Button(
            right_button_frame,
            text=self._tr("Save Mapping"),
            command=lambda: self._save_mapping(name_var, mapping_window)
        ).pack(side="right", padx=5)
    
    def _add_mapping_row(self, parent_frame):
        """添加单个映射行"""
        row_frame = ttk.Frame(parent_frame)
        row_frame.pack(fill="x", pady=2)
        
        orig_var = tk.StringVar()
        mapped_var = tk.StringVar()
        
        ttk.Entry(row_frame, textvariable=orig_var, width=15).pack(side="left", padx=2)
        ttk.Label(row_frame, text="→", width=5).pack(side="left", padx=2)
        ttk.Entry(row_frame, textvariable=mapped_var, width=15).pack(side="left", padx=2)
        
        self.mapping_entries.append((orig_var, mapped_var))
        
        # 更新滚动区域
        parent_frame.master.see("end")  # 滚动到底部
    
    def _load_existing_mapping(self, name_var, scrollable_frame):
        """加载现有映射"""
        mapping_name = name_var.get()
        if mapping_name in self.custom_mappings:
            # 清除现有行
            for widget in scrollable_frame.winfo_children():
                widget.destroy()
            
            self.mapping_entries = []
            
            # 添加映射行
            for orig, mapped in self.custom_mappings[mapping_name].items():
                self._add_mapping_row(scrollable_frame)
                self.mapping_entries[-1][0].set(orig)
                self.mapping_entries[-1][1].set(mapped)
    
    def _generate_random_mapping(self, scrollable_frame):
        """随机生成映射"""
        # 清除现有行
        for widget in scrollable_frame.winfo_children():
            widget.destroy()
        
        self.mapping_entries = []
        
        # 创建包含所有可打印ASCII字符的列表
        chars = list(string.ascii_letters + string.digits + string.punctuation)
        random.shuffle(chars)
        
        # 确保字符数量是偶数
        if len(chars) % 2 != 0:
            chars.pop()
        
        # 分成两半，创建映射
        half = len(chars) // 2
        for orig, mapped in zip(chars[:half], chars[half:]):
            self._add_mapping_row(scrollable_frame)
            self.mapping_entries[-1][0].set(orig)
            self.mapping_entries[-1][1].set(mapped)
    
    def _save_mapping(self, name_var, window):
        """保存映射"""
        mapping_name = name_var.get()
        if not mapping_name:
            messagebox.showwarning(self._tr("Warning"), self._tr("Please enter a mapping name"))
            return
        
        new_mapping = {}
        has_content = False
        
        for orig_var, mapped_var in self.mapping_entries:
            orig = orig_var.get().strip()
            mapped = mapped_var.get().strip()
            
            if orig and mapped:
                if len(orig) != 1 or len(mapped) != 1:
                    messagebox.showwarning(self._tr("Warning"), self._tr("Each mapping should be single character"))
                    return
                new_mapping[orig] = mapped
                has_content = True
        
        if not has_content:
            messagebox.showwarning(self._tr("Warning"), self._tr("No valid mappings to save"))
            return
        
        self.custom_mappings[mapping_name] = new_mapping
        self._save_custom_mappings()
        self.custom_charset.set(mapping_name)
        window.destroy()
        messagebox.showinfo(self._tr("Success"), self._tr("Mapping saved successfully"))

    def _save_custom_mappings(self):
        """保存自定义映射到文件"""
        try:
            with open(os.path.join(self.program_dir, "custom_mappings.json"), 'w', encoding='utf-8') as f:
                json.dump(self.custom_mappings, f, indent=4, ensure_ascii=False)
        except Exception as e:
            messagebox.showerror(self._tr("Error"), f"{self._tr('Failed to save mappings')}: {str(e)}")

    def save_result(self):
        """保存结果到文件"""
        result = self.output_text.get("1.0", tk.END).strip()
        if not result:
            messagebox.showwarning(self._tr("Warning"), self._tr("No result to save"))
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(result)
                messagebox.showinfo(self._tr("Success"), self._tr("Result saved successfully"))
            except IOError as e:
                messagebox.showerror(self._tr("Error"), 
                                   f"{self._tr('Failed to save file')}: {str(e)}")

    def show_history(self):
        """显示历史记录"""
        history_path = os.path.join(self.program_dir, "History.txt")
        if not os.path.exists(history_path):
            messagebox.showinfo(self._tr("History"), self._tr("No history records"))
            return
        
        history_window = tk.Toplevel(self.root)
        history_window.title(self._tr("History"))
        
        text_frame = tk.Frame(history_window)
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side="right", fill="y")
        
        history_text = tk.Text(text_frame, wrap="word", yscrollcommand=scrollbar.set,
                             font=('Bender', 10), padx=5, pady=5)
        history_text.pack(fill="both", expand=True)
        
        scrollbar.config(command=history_text.yview)
        
        try:
            with open(history_path, 'r', encoding='utf-8') as f:
                history_text.insert("1.0", f.read())
        except Exception as e:
            messagebox.showerror(self._tr("Error"), f"{self._tr('Failed to load history')}: {str(e)}")
        
        history_text.config(state="disabled")

    def clear_io(self):
        """清空输入输出"""
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)

    def apply_settings(self):
        """应用设置"""
        # 应用语言设置
        new_lang = self.lang_var.get()
        if new_lang != self.current_language:
            self.current_language = new_lang
            self.settings["language"] = new_lang
            self._save_settings()
            self._update_ui_language()
            messagebox.showinfo(self._tr("Success"), 
                              self._tr("Language changed. Please restart the program for full effect."))
        # 应用窗口尺寸设置
        if "window_size" in self.settings:
            self.root.geometry(self.settings["window_size"])

    def _save_settings(self):
        """保存设置到文件"""
        try:
            with open(os.path.join(self.program_dir, "settings.json"), 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=4, ensure_ascii=False)
        except Exception as e:
            messagebox.showerror(self._tr("Error"), f"{self._tr('Failed to save settings')}: {str(e)}")

    def _update_ui_language(self):
        """更新界面语言"""
        # 更新标签页标题
        for i in range(self.notebook.index("end")):
            tab_text = self.notebook.tab(i, "text")
            translated = self._tr(tab_text)
            if translated != tab_text:
                self.notebook.tab(i, text=translated)
        
        # 这里可以添加其他需要更新语言的UI元素

    def import_language_pack(self):
        """导入语言包"""
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    lang_pack = json.load(f)
                
                lang_code = lang_pack.get("language_code")
                if lang_code:
                    # 保存到localization目录
                    dest_file = os.path.join(self.program_dir, "localization", f"{lang_code}.json")
                    with open(dest_file, 'w', encoding='utf-8') as f:
                        json.dump(lang_pack, f, indent=4, ensure_ascii=False)
                    
                    # 重新加载本地化文件
                    self._load_localization_files()
                    messagebox.showinfo(self._tr("Success"), 
                                      self._tr("Language pack imported successfully"))
                else:
                    messagebox.showerror(self._tr("Error"), 
                                       self._tr("Invalid language pack format"))
            except Exception as e:
                messagebox.showerror(self._tr("Error"), 
                                   f"{self._tr('Failed to load language pack')}: {str(e)}")

def main():
    """Main entry point for the application"""
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
    
if __name__ == "__main__":
    main()
