import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import struct
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets

class Plugin:
    def __init__(self, app):
        self.app = app
        self.name = "文件嵌入工具"
        self.mutation_key = None
        
    def setup_ui(self, parent):
        """设置插件界面"""
        self.parent = parent
        
        # 主框架
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # 创建标签页
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill="both", expand=True)
        
        # 创建文件嵌入标签页
        self.create_embed_tab()
        
        # 创建文件拆解标签页
        self.create_extract_tab()
        
    def create_embed_tab(self):
        """创建文件嵌入标签页"""
        embed_tab = ttk.Frame(self.notebook)
        self.notebook.add(embed_tab, text="文件嵌入")
        
        # 文件选择区域
        file_frame = ttk.LabelFrame(embed_tab, text="文件选择")
        file_frame.pack(fill="x", padx=5, pady=5)
        
        # 表文件选择
        ttk.Label(file_frame, text="表文件:").grid(row=0, column=0, sticky="w")
        self.outer_file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.outer_file_var, width=40).grid(row=0, column=1, padx=5)
        ttk.Button(file_frame, text="浏览", command=self._browse_outer_file).grid(row=0, column=2)
        
        # 里文件选择
        ttk.Label(file_frame, text="里文件:").grid(row=1, column=0, sticky="w")
        self.inner_file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.inner_file_var, width=40).grid(row=1, column=1, padx=5)
        ttk.Button(file_frame, text="浏览", command=self._browse_inner_file).grid(row=1, column=2)
        
        # 异变参数设置
        self.mutation_frame = ttk.LabelFrame(embed_tab, text="异变参数 (可选)")
        self.mutation_frame.pack(fill="x", padx=5, pady=5)
        
        # 显示/隐藏复选框
        self.show_key_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.mutation_frame, text="显示异变参数", 
                       variable=self.show_key_var, 
                       command=self.toggle_key_visibility).grid(row=0, column=0, sticky="w", columnspan=3)
        
        ttk.Label(self.mutation_frame, text="异变密钥:").grid(row=1, column=0, sticky="w")
        self.mutation_key_var = tk.StringVar()
        self.key_entry = ttk.Entry(self.mutation_frame, textvariable=self.mutation_key_var, 
                                 show="*", width=30)
        self.key_entry.grid(row=1, column=1, sticky="w")
        
        ttk.Button(self.mutation_frame, text="生成随机密钥", 
                  command=self._generate_random_key).grid(row=1, column=2, padx=5)
        
        # 操作按钮
        button_frame = ttk.Frame(embed_tab)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="创建奇美拉文件", command=self.create_chimera).pack(side="left", padx=5)
        ttk.Button(button_frame, text="清空选择", command=self.clear_files).pack(side="left", padx=5)
        
        # 状态显示
        self.status_var = tk.StringVar()
        ttk.Label(embed_tab, textvariable=self.status_var).pack(pady=5)
        
    def create_extract_tab(self):
        """创建文件拆解标签页"""
        extract_tab = ttk.Frame(self.notebook)
        self.notebook.add(extract_tab, text="文件拆解")
        
        # 文件选择区域
        file_frame = ttk.LabelFrame(extract_tab, text="选择奇美拉文件")
        file_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(file_frame, text="奇美拉文件:").grid(row=0, column=0, sticky="w")
        self.chimera_file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.chimera_file_var, width=40).grid(row=0, column=1, padx=5)
        ttk.Button(file_frame, text="浏览", command=self._browse_chimera_file).grid(row=0, column=2)
        
        # 异变参数设置
        self.extract_mutation_frame = ttk.LabelFrame(extract_tab, text="异变参数 (如加密时使用过)")
        self.extract_mutation_frame.pack(fill="x", padx=5, pady=5)
        
        # 显示/隐藏复选框
        self.extract_show_key_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.extract_mutation_frame, text="显示异变参数", 
                       variable=self.extract_show_key_var, 
                       command=self.toggle_extract_key_visibility).grid(row=0, column=0, sticky="w", columnspan=3)
        
        ttk.Label(self.extract_mutation_frame, text="异变密钥:").grid(row=1, column=0, sticky="w")
        self.extract_key_var = tk.StringVar()
        self.extract_key_entry = ttk.Entry(self.extract_mutation_frame, 
                                         textvariable=self.extract_key_var, 
                                         show="*", width=30)
        self.extract_key_entry.grid(row=1, column=1, sticky="w")
        
        # 操作按钮
        button_frame = ttk.Frame(extract_tab)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="拆解文件", command=self.extract_files).pack(side="left", padx=5)
        
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
        filename = filedialog.askopenfilename(title="选择表文件")
        if filename:
            self.outer_file_var.set(filename)
            self.status_var.set(f"已选择表文件: {os.path.basename(filename)}")
            
    def _browse_inner_file(self):
        """选择里文件"""
        filename = filedialog.askopenfilename(title="选择里文件")
        if filename:
            self.inner_file_var.set(filename)
            self.status_var.set(f"已选择里文件: {os.path.basename(filename)}")
            
    def _browse_chimera_file(self):
        """选择奇美拉文件"""
        filename = filedialog.askopenfilename(title="选择奇美拉文件")
        if filename:
            self.chimera_file_var.set(filename)
            self.extract_status_var.set(f"已选择奇美拉文件: {os.path.basename(filename)}")
            
    def _generate_random_key(self):
        """生成随机异变密钥"""
        key = secrets.token_hex(16)
        self.mutation_key_var.set(key)
        self.status_var.set("已生成随机异变密钥")
            
    def clear_files(self):
        """清空已选文件"""
        self.outer_file_var.set("")
        self.inner_file_var.set("")
        self.mutation_key_var.set("")
        self.status_var.set("已清空文件选择")
        
    def create_chimera(self):
        """创建奇美拉文件"""
        outer_file = self.outer_file_var.get()
        inner_file = self.inner_file_var.get()
        
        if not outer_file or not inner_file:
            messagebox.showerror("错误", "请同时选择表文件和里文件")
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
                filetypes=[("奇美拉文件", "*.chimera"), ("所有文件", "*.*")],
                title="保存奇美拉文件"
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
            
            self.status_var.set(f"奇美拉文件创建成功: {os.path.basename(output_file)}")
            messagebox.showinfo("成功", "奇美拉文件创建成功!")
            
        except Exception as e:
            messagebox.showerror("错误", f"创建奇美拉文件失败: {str(e)}")
            self.status_var.set("创建奇美拉文件时出错")
            
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
            messagebox.showerror("错误", "请选择奇美拉文件")
            return
            
        try:
            # 读取奇美拉文件
            with open(chimera_file, 'rb') as f:
                header = f.read(8)
                if header != b'CHIMERA\x00':
                    raise ValueError("无效的奇美拉文件格式")
                    
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
                    messagebox.showerror("错误", "此文件使用了异变参数，请输入正确的异变密钥")
                    return
                    
                try:
                    outer_data = self._demutate_data(outer_data, mutation_key)
                    inner_data = self._demutate_data(inner_data, mutation_key)
                except Exception as e:
                    messagebox.showerror("错误", f"解密失败: {str(e)}\n可能是异变密钥不正确")
                    return
                    
            # 创建输出目录
            output_dir = os.path.join(self.app.program_dir, "Output")
            os.makedirs(output_dir, exist_ok=True)
            
            # 保存表文件
            outer_path = os.path.join(output_dir, outer_name)
            with open(outer_path, 'wb') as f:
                f.write(outer_data)
                
            # 保存里文件
            inner_path = os.path.join(output_dir, inner_name)
            with open(inner_path, 'wb') as f:
                f.write(inner_data)
                
            self.extract_status_var.set(f"文件拆解成功，保存在: {output_dir}")
            messagebox.showinfo("成功", f"文件拆解成功!\n表文件: {outer_name}\n里文件: {inner_name}")
            
        except Exception as e:
            messagebox.showerror("错误", f"拆解文件失败: {str(e)}")
            self.extract_status_var.set("拆解文件时出错")
            
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

def main():
    """测试用主函数"""
    root = tk.Tk()
    app = type('DummyApp', (), {'program_dir': os.getcwd()})()  # 创建模拟app对象
    plugin = Plugin(app)
    
    # 创建测试窗口
    test_window = tk.Toplevel(root)
    plugin.setup_ui(test_window)
    
    root.mainloop()

if __name__ == "__main__":
    main()
