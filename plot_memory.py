# plot_memory.py
import psutil
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import argparse
import time
from datetime import datetime

def monitor_process(process_pid, interval=2, duration=300):
    """Monitor memory usage of a specific process"""
    print(f"ðŸ” Monitoring process: {process_pid}")
    print(f"â± Sampling every {interval}s for {duration//60} minutes")
    
    data = []
    end_time = time.time() + duration
    
    while time.time() < end_time:
        found = False
        timestamp = datetime.now()
        
        for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
            if process_pid.lower() in proc.info['pid'].lower():
                mem = proc.info['memory_info'].rss / (1024 * 1024)  # Convert to MB
                data.append({
                    'Timestamp': timestamp,
                    'Memory (MB)': round(mem, 2),
                    'PID': proc.info['pid']
                })
                found = True
                break
        
        if not found:
            print(f"âš ï¸ Process '{process_pid}' not found! Retrying...")
        
        time.sleep(interval)
    
    return pd.DataFrame(data)

def plot_memory(df, process_pid):
    """Plot memory usage with professional styling"""
    plt.style.use('seaborn-v0_8-darkgrid')
    fig, ax = plt.subplots(figsize=(14, 8), facecolor='#f0f0f0')
    
    fig.suptitle(f'Memory Usage: {process_pid}', y=0.95, 
                fontsize=18, fontweight='bold')
    
    ax.plot(df['Timestamp'], df['Memory (MB)'], 
            color='#3498db', linewidth=2.5, marker='o',
            markersize=5, markerfacecolor='#2980b9')
    
    # Formatting
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    ax.xaxis.set_major_locator(mdates.SecondLocator(interval=30))
    plt.xticks(rotation=45, ha='right')
    
    ax.set_ylabel('Memory Usage (MB)', fontsize=12)
    ax.grid(True, linestyle='--', alpha=0.7)
    
    # Annotations
    avg_mem = df['Memory (MB)'].mean()
    ax.annotate(f'Avg: {avg_mem:.2f} MB', 
                xy=(0.98, 0.95), xycoords='axes fraction',
                ha='right', va='top', fontsize=12,
                bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))
    
    plt.tight_layout()
    plt.savefig(f'memory_usage_{process_pid}.png', dpi=300)
    plt.show()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process memory monitor')
    parser.add_argument('process', help='Process name to monitor')
    parser.add_argument('-i', '--interval', type=int, default=2,
                        help='Sampling interval in seconds (default: 2)')
    parser.add_argument('-d', '--duration', type=int, default=300,
                        help='Monitoring duration in seconds (default: 300)')
    
    args = parser.parse_args()
    
    print("ðŸ•µï¸ Starting process memory monitor...")
    df = monitor_process(args.process, args.interval, args.duration)
    
    if not df.empty:
        print("\nðŸ“ˆ Plotting results...")
        plot_memory(df, args.process)
        df.to_csv(f'memory_usage_{args.process}.csv', index=False)
        print(f"ðŸ’¾ Data saved to memory_usage_{args.process}.csv")
    else:
        print("âŒ No data collected - process not found")