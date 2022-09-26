import curses

# Just strings for testing
packets = [
    "Option 1 looking kinda fun! BARS",
    "Geese are tasty, not ducks.",
    "abcdefghijklmnopqrstyxqz",
    "That's not the alphabet???",
    "Okay fair enough"
    ]
blocked_urls = [
    "This isn't a url?",
    "ebay.ie/12319239123",
    "http://www.amazon.com/yay",
    "https://tcd.blackboard.com/webapps/blackboard/",
    "https://tcd.blackboard.com/",
    "https://docs.python.org/3/howto/curses.html",
    "https://www.google.com/",
    "https://www.amazon.de/",
    "More non URLs cause why not",
    "Woohooooooooo",
    "Is this more tests wtf?>??",
    "Wow how did you get all the way down here?",
    "This is the end...",
    "Or is it?",
    "Now it is!"]

CONSOLE_WINDOW_ID = False
BLOCKED_WINDOW_ID = True

def draw_keymap(window):
    window.erase()
    window.border()
    window.addstr(0, int(curses.COLS / 4) - 4, " Keymap ")
    window.addstr(1, 1, "[Q] - Quit")
    window.addstr(2, 1, "[S] - Switch window")
    window.addstr(3, 1, "[B] - Block URL (of selected packet)")
    window.addstr(4, 1, "[U] - Unblock URL")
    window.addstr(5, 1, "[Ent/Esc] - View detailed packet info")
    window.addstr(6, 1, "[Up/Down Arrow] - Select packet or URL")
    window.refresh()

def draw_blocked(window, selected_url, focused_window, block_min, block_max):
    window.erase()
    window.border()
    window.addstr(0, int(curses.COLS / 4) - 7, " Blocked URLs ")

    # List of blocked URLs
    b_pos = 1
    for b in range(block_min, block_max + 1):
        window.addstr(b_pos, 1, "[" + str(b) + "] " + blocked_urls[b],
            curses.A_REVERSE if (b == selected_url and focused_window == BLOCKED_WINDOW_ID) else curses.A_NORMAL)
        b_pos = b_pos + 1
    window.refresh()

def draw_console(window, selected_packet, focused_window, packet_min, packet_max):
    window.erase()
    window.border()
    window.addstr(0, int(curses.COLS / 2) - 10, " Management Console ")

    # List of packets
    p_pos = 1
    for p in range(packet_min, packet_max + 1):
        window.addstr(p_pos, 1, "[" + str(p) + "] " + packets[p],
            curses.A_REVERSE if (p == selected_packet and focused_window == CONSOLE_WINDOW_ID) else curses.A_NORMAL)
        p_pos = p_pos + 1
    window.refresh()

def app(stdscr):
    # Options
    curses.curs_set(0)

    # Window Creation
    console_window = curses.newwin(curses.LINES - int(curses.LINES / 3), curses.COLS, 0, 0)
    keymap_window = curses.newwin(int(curses.LINES / 3), int(curses.COLS / 2), curses.LINES - int(curses.LINES / 3), 0)
    blocked_window = curses.newwin(int(curses.LINES / 3), int(curses.COLS / 2), curses.LINES - int(curses.LINES / 3), int(curses.COLS / 2))
    focused_window = False # False for console, True for blocked urls
    selected_packet = 0
    selected_url = 0

    max_urls = int(curses.LINES / 3) - 2 # Max number of URLs that can be displayed on the screen at once
    block_min = 0
    block_max = len(blocked_urls) - 1 if len(blocked_urls) < max_urls else max_urls - 1

    max_packets = curses.LINES - int(curses.LINES / 3) - 2 # Max number of packets that can be displayed on the screen at once
    packet_min = 0
    packet_max = len(packets) - 1 if len(packets) < max_packets else max_packets - 1

    while True:
        # Draw Windows
        stdscr.erase()
        stdscr.refresh()
        draw_console(console_window, selected_packet, focused_window, packet_min, packet_max)
        draw_keymap(keymap_window)
        draw_blocked(blocked_window, selected_url, focused_window, block_min, block_max)

        # Handle Input
        c = stdscr.getch()
        if c == ord('q'):
            break
        elif c == ord('s'):
            focused_window = not focused_window
        elif c == curses.KEY_DOWN:
            if focused_window == CONSOLE_WINDOW_ID and selected_packet < len(packets) - 1:
                selected_packet = selected_packet + 1
                if selected_packet > packet_max:
                    packet_max = packet_max + 1
                    packet_min = packet_min + 1
            elif focused_window == BLOCKED_WINDOW_ID and selected_url < len(blocked_urls) - 1:
                selected_url  = selected_url + 1
                if selected_url > block_max:
                    block_max = block_max + 1
                    block_min = block_min + 1
        elif c == curses.KEY_UP:
            if focused_window == CONSOLE_WINDOW_ID and selected_packet > 0:
                selected_packet = selected_packet - 1
                if selected_packet < packet_min:
                    packet_max = packet_max - 1
                    packet_min = packet_min - 1
            elif focused_window == BLOCKED_WINDOW_ID and selected_url > 0:
                selected_url = selected_url - 1
                if selected_url < block_min:
                    block_max = block_max - 1
                    block_min = block_min - 1

if __name__ == "__main__":
    curses.wrapper(app)