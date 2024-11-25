# threading_utils.py
import threading
from queue import Queue

class ThreadPool:
    def __init__(self, num_threads):
        """
        스레드 풀 초기화
        :param num_threads: 사용할 스레드 수
        """
        self.tasks = Queue()
        self.results = []
        self.results_lock = threading.Lock()
        self.threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=self.worker)
            thread.daemon = True
            thread.start()
            self.threads.append(thread)

    def worker(self):
        """
        큐에서 작업을 가져와 실행하는 작업자 함수
        """
        while True:
            func, args = self.tasks.get()
            if func is None:
                break
            result = func(*args)
            with self.results_lock:
                self.results.append(result)
            self.tasks.task_done()

    def add_task(self, func, *args):
        """
        작업을 큐에 추가
        :param func: 실행할 함수
        :param args: 함수에 전달할 인자들
        """
        self.tasks.put((func, args))

    def wait_completion(self):
        """
        모든 작업이 완료될 때까지 대기
        """
        self.tasks.join()
        # 작업 종료를 위해 각 스레드에 None 작업 추가
        for _ in self.threads:
            self.add_task(None)
        for thread in self.threads:
            thread.join()

    def get_results(self):
        """
        모든 결과 반환
        :return: 결과 리스트
        """
        return self.results
