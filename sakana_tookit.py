import tkinter as tk
from tkinter import ttk, messagebox, filedialog, font as tkfont
import json
import os
import sys
import locale
from datetime import datetime
import importlib.util
import inspect
import random
import string

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Sakana Toolkit")
        
        # 程序元信息
        self.version = "0.1.0.7"
        self.author = "KArabella"
        
        # 初始化基本属性
        self.history = []
        self.custom_mappings = {}
        self.plugins = {}
        
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
        
        # 先创建设置页
        self._setup_settings_tab()
        
        # 再创建其他标签页
        self._setup_caesar_tab()
        
        # 最后加载插件
        self._load_builtin_plugins()
        
        # 确保设置页在最前
        self.notebook.select(0)
        
        # 初始化后更新UI语言
        self._update_ui_language()

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
            "Plugin Settings": "插件设置",
            "Import Plugin": "导入插件",
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
            "Plugin imported successfully": "插件导入成功",
            "Invalid plugin structure": "无效的插件结构",
            "Plugin class not found": "未找到插件类",
            "Failed to load plugin": "加载插件失败",
            "Language pack imported successfully": "语言包导入成功",
            "Invalid language pack format": "无效的语言包格式",
            "Failed to load language pack": "加载语言包失败",
            "Failed to save history": "保存历史记录失败",
            "Failed to load history": "加载历史记录失败",
            "Failed to save settings": "保存设置失败",
            "Language changed. Please restart the program for full effect.": "语言已更改，请重启程序使更改完全生效",
            "No plugin selected": "未选择插件",
            "Confirm Uninstall": "确认卸载",
            "Are you sure you want to uninstall plugin: {}?": "确定要卸载插件: {} 吗?",
            "Plugin uninstalled successfully": "插件卸载成功",
            "Failed to uninstall plugin": "卸载插件失败",
            "Uninstall Plugin": "卸载插件",
            "Please enter a mapping name": "请输入映射名称",
            "Each mapping should be single character": "每个映射应为单个字符",
            "No valid mappings to save": "没有有效的映射可保存",
            "Generate Random Mapping": "随机生成映射"
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
            "Plugin Settings": "Plugin Settings",
            "Import Plugin": "Import Plugin",
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
            "Plugin imported successfully": "Plugin imported successfully",
            "Invalid plugin structure": "Invalid plugin structure",
            "Plugin class not found": "Plugin class not found",
            "Failed to load plugin": "Failed to load plugin",
            "Language pack imported successfully": "Language pack imported successfully",
            "Invalid language pack format": "Invalid language pack format",
            "Failed to load language pack": "Failed to load language pack",
            "Failed to save history": "Failed to save history",
            "Failed to load history": "Failed to load history",
            "Failed to save settings": "Failed to save settings",
            "Language changed. Please restart the program for full effect.": "Language changed. Please restart the program for full effect.",
            "No plugin selected": "No plugin selected",
            "Confirm Uninstall": "Confirm Uninstall",
            "Are you sure you want to uninstall plugin: {}?": "Are you sure you want to uninstall plugin: {}?",
            "Plugin uninstalled successfully": "Plugin uninstalled successfully",
            "Failed to uninstall plugin": "Failed to uninstall plugin",
            "Uninstall Plugin": "Uninstall Plugin",
            "Please enter a mapping name": "Please enter a mapping name",
            "Each mapping should be single character": "Each mapping should be single character",
            "No valid mappings to save": "No valid mappings to save",
            "Generate Random Mapping": "Generate Random Mapping"
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
        os.makedirs(os.path.join(self.program_dir, "plugins"), exist_ok=True)
        
        # 初始化默认文件
        if not os.path.exists(os.path.join(self.program_dir, "settings.json")):
            with open(os.path.join(self.program_dir, "settings.json"), 'w', encoding='utf-8') as f:
                json.dump({
                    "language": self.current_language,
                    "window_size": "800x600",
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
                return json.load(f)
        except:
            return {
                "language": self.current_language,
                "window_size": "800x600",
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
    
        # 插件设置
        plugin_frame = ttk.LabelFrame(self.settings_tab, text=self._tr("Plugin Settings"))
        plugin_frame.pack(fill="x", padx=10, pady=5)
        
        # 单列布局防止重复
        plugin_grid = ttk.Frame(plugin_frame)
        plugin_grid.pack(fill="x")

        # 导入按钮
        ttk.Button(plugin_grid, text=self._tr("Import Plugin"),
                 command=self.import_plugin).grid(row=0, column=0, pady=5, sticky="w")

        # 插件选择下拉框
        self.plugin_var = tk.StringVar()
        self.plugin_list_widget = ttk.Combobox(plugin_grid, 
                                            textvariable=self.plugin_var, 
                                            state="readonly")
        self.plugin_list_widget.grid(row=1, column=0, pady=5, sticky="ew")
        
        # 卸载按钮 (确保只有一个)
        ttk.Button(plugin_grid, text=self._tr("Uninstall Plugin"),
                 command=lambda: self.uninstall_plugin(self.plugin_list_widget)).grid(row=2, column=0, pady=5, sticky="w")

        # 配置网格列权重
        plugin_grid.columnconfigure(0, weight=1)
        
        # 初始化列表
        self._update_plugin_list(self.plugin_list_widget)
    
        # 应用按钮
        ttk.Button(self.settings_tab, text=self._tr("Apply Settings"),
                 command=self.apply_settings).pack(pady=10)

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
        
        # 滚动区域
        canvas = tk.Canvas(table_frame)
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
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
        parent_frame.master.master.yview_moveto(1.0)  # 滚动到底部
    
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
            messagebox.showinfo(self._tr("Success"), self._tr("Language changed. Please restart the program for full effect."))

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

    def import_plugin(self):
        """导入用户插件"""
        filename = filedialog.askopenfilename(
            filetypes=[("Python files", "*.py"), ("All files", "*.*")])
        
        if filename:
            try:
                # 复制插件到plugins目录
                plugin_name = os.path.splitext(os.path.basename(filename))[0]
                dest_file = os.path.join(self.program_dir, "plugins", f"{plugin_name}.py")
                
                # 如果是新文件或不同位置的文件才复制
                if not os.path.exists(dest_file) or not os.path.samefile(filename, dest_file):
                    with open(filename, 'r', encoding='utf-8') as src, \
                         open(dest_file, 'w', encoding='utf-8') as dst:
                        dst.write(src.read())
                
                # 加载插件
                spec = importlib.util.spec_from_file_location(plugin_name, dest_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                if hasattr(module, "Plugin"):
                    plugin_class = module.Plugin
                    if inspect.isclass(plugin_class):
                        plugin_instance = plugin_class(self)
                        self.plugins[plugin_name] = plugin_instance
                        
                        plugin_tab = ttk.Frame(self.notebook)
                        self.notebook.add(plugin_tab, text=plugin_name)
                        
                        if hasattr(plugin_instance, "setup_ui"):
                            plugin_instance.setup_ui(plugin_tab)
                        
                        messagebox.showinfo(self._tr("Success"), 
                                          self._tr("Plugin imported successfully"))
                    else:
                        messagebox.showerror(self._tr("Error"), 
                                           self._tr("Invalid plugin structure"))
                else:
                    messagebox.showerror(self._tr("Error"), 
                                       self._tr("Plugin class not found"))
            except Exception as e:
                messagebox.showerror(self._tr("Error"), 
                                   f"{self._tr('Failed to load plugin')}: {str(e)}")

    def _load_builtin_plugins(self):
        """加载内置插件"""
        plugins_dir = os.path.join(self.program_dir, "plugins")
        if os.path.exists(plugins_dir):
            for filename in os.listdir(plugins_dir):
                if filename.endswith('.py') and filename != "example_plugin.py":
                    try:
                        plugin_name = os.path.splitext(filename)[0]
                        spec = importlib.util.spec_from_file_location(
                            plugin_name, os.path.join(plugins_dir, filename))
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        
                        if hasattr(module, "Plugin"):
                            plugin_class = module.Plugin
                            if inspect.isclass(plugin_class):
                                plugin_instance = plugin_class(self)
                                self.plugins[plugin_name] = plugin_instance
                                
                                # 添加插件标签页（但不立即显示）
                                plugin_tab = ttk.Frame(self.notebook)
                                self.notebook.add(plugin_tab, text=plugin_name)
                                
                                if hasattr(plugin_instance, "setup_ui"):
                                    plugin_instance.setup_ui(plugin_tab)
                                
                                # 刷新列表但不切换页面
                                if hasattr(self, 'plugin_list_widget'):
                                    self._update_plugin_list(self.plugin_list_widget)
                    except Exception as e:
                        print(f"加载插件 {filename} 失败: {str(e)}")
        
        # 加载完成后确保设置页在最前
        self.notebook.select(0)
                        
    def _update_plugin_list(self, combobox):
        """更新插件下拉列表"""
        plugins = list(self.plugins.keys())
        combobox['values'] = plugins
        if plugins:
            combobox.current(0)
        else:
            self.plugin_var.set("")  # 清空选择

    def uninstall_plugin(self, plugin_list):
        """卸载选中的插件"""
        if not hasattr(self, 'plugin_list_widget'):
            return
                
        plugin_name = self.plugin_var.get()
        if not plugin_name:
            messagebox.showwarning(self._tr("Warning"), self._tr("No plugin selected"))
            return
        
        # 二次确认
        if not messagebox.askyesno(
            self._tr("Confirm Uninstall"),
            self._tr("Are you sure you want to uninstall plugin: {}?").format(plugin_name)
        ):
            return
        
        try:
            # 从界面移除
            for i in range(self.notebook.index("end")):
                if self.notebook.tab(i, "text") == plugin_name:
                    self.notebook.forget(i)
                    break
            
            # 从内存移除
            if plugin_name in self.plugins:
                del self.plugins[plugin_name]
            
            # 从磁盘删除
            plugin_file = os.path.join(self.program_dir, "plugins", f"{plugin_name}.py")
            if os.path.exists(plugin_file):
                os.remove(plugin_file)
            
            # 更新列表
            self._update_plugin_list(plugin_list)
            messagebox.showinfo(self._tr("Success"), 
                              self._tr("Plugin uninstalled successfully"))
        except Exception as e:
            messagebox.showerror(self._tr("Error"), 
                               f"{self._tr('Failed to uninstall plugin')}: {str(e)}")
            
        self._update_plugin_list(self.plugin_list_widget)
        
def main():
    """Main entry point for the application"""
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
    
if __name__ == "__main__":
    main()
