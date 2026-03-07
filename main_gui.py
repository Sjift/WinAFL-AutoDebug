"""
AutoDebug v3 - GUI 진입점 (main_gui.py)

CustomTkinter 기반 대시보드 GUI를 실행한다.

사용법:
    python main_gui.py
    python main_gui.py --config my_config.yaml
"""

import sys
import argparse
from gui.main_window import MainWindow


def main():
    """GUI 메인 실행 함수."""
    parser = argparse.ArgumentParser(description='AutoDebug v3 - GUI 모드')
    parser.add_argument('--config', default='config.yaml', help='설정 파일 경로')
    args = parser.parse_args()

    app = MainWindow(config_path=args.config)
    app.mainloop()


if __name__ == '__main__':
    main()
