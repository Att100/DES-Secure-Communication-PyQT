import base64
from io import BytesIO
import sys
import base64
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

from des_backend import *
from socket_backend import *


class DataTable(QWidget):
    def __init__(self, parent) -> None:
        super().__init__(parent)

        self.data = []
        self.row_ids = []

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(['sender', 'data', 'type', 'status', 'operation'])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        QTableWidget.resizeColumnsToContents(self.table)
        QTableWidget.resizeRowsToContents(self.table)

        layout = QHBoxLayout()
        layout.addWidget(self.table)
        self.setLayout(layout)

        self.callback = None
        self.del_callback = None

    def set_callbacks(self, handle_data_retrieve, del_row):
        self.callback = handle_data_retrieve
        self.del_callback = del_row

    def make_buttons(self, type, id):
        widget = QWidget()
        if type == 'file':
            op_btn = QPushButton('save')
        else:
            op_btn = QPushButton('copy')
        op_btn.clicked.connect(lambda: self.callback(id))
        op_btn.setStyleSheet("QPushButton{height: 25px}")
        del_btn = QPushButton('del')
        del_btn.clicked.connect(lambda: self.del_callback(id))
        del_btn.setStyleSheet("QPushButton{height: 25px}")

        layout = QHBoxLayout()
        layout.addWidget(op_btn)
        layout.addWidget(del_btn)
        layout.setContentsMargins(5,2,5,2)
        widget.setLayout(layout)
        return widget

    def add_new_row(self, data: dict):
        self.data.append(data)
        sender = QTableWidgetItem(data['sender'])
        filename = QTableWidgetItem(data['data'])
        status = QTableWidgetItem(str(data['status']))
        type = QTableWidgetItem(data['type'])
        if data['type'] == 'file':
            type.setForeground(QBrush(Qt.red))
        else:
            type.setForeground(QBrush(Qt.green))

        if len(self.row_ids) == 0:
            self.row_ids.append(0)
        else:
            self.row_ids.append(self.row_ids[-1]+1)

        fake_row_id = len(self.row_ids)-1
        real_row_id = self.row_ids[-1]
        self.table.insertRow(real_row_id)
        self.table.setItem(real_row_id, 0, sender)
        self.table.setItem(real_row_id, 1, filename)
        self.table.setItem(real_row_id, 2, type)
        self.table.setItem(real_row_id, 3, status)
        op_btns = self.make_buttons(data['type'], fake_row_id)
        self.table.setCellWidget(real_row_id, 4, op_btns)

        
class App(QWidget):
    """
    DES-secure communication GUI class
    """
    def __init__(self) -> None:
        super().__init__()

        self.make_ui()
        self.set_onclick_listeners()

        self.server = None
        self.server_thread = None
        self.client = None
        self.client_thread = None
        self.connected = False

        if not os.path.exists("./cache"):
            os.mkdir("./cache")

    def make_ui(self):
        self.data_table = DataTable(self)
        self.data_table.setGeometry(20, 20, 1045, 300)
        self.data_table.set_callbacks(
            self.handle_data_retrieve,
            self.handle_remove_row)

        self.session_label = QLabel("session", self)
        self.session_label.setGeometry(32, 320, 60, 30)
        self.ses_edit = QLineEdit(self)
        self.ses_edit.setGeometry(100, 320, 410, 30)

        self.role_select = QComboBox(self)
        self.role_select.addItems(['server', 'client'])
        self.role_select.setGeometry(525, 320, 200, 30)

        self.connect_btn = QPushButton("connect", self)
        self.connect_btn.setGeometry(770, 320, 130, 30)
        self.clear_ses_btn = QPushButton("clear", self)
        self.clear_ses_btn.setGeometry(920, 320, 130, 30)

        self.content_input_label = QLabel("content", self)
        self.content_input_label.setGeometry(32, 360, 60, 30)
        self.content_edit = QTextEdit(self)
        self.content_edit.setGeometry(100, 360, 625, 100)

        self.path_label = QLabel("file", self)
        self.path_label.setGeometry(32, 470, 60, 30)
        self.path_edit = QLineEdit(self)
        self.path_edit.setGeometry(100, 470, 410, 30)

        self.file_btn = QPushButton("open", self)
        self.file_btn.setGeometry(525, 470, 200, 30)

        self.enc_dec_bar = QProgressBar(self)
        self.enc_dec_bar.setGeometry(770, 400, 290, 30)
        self.enc_dec_bar.setMaximum(100) 
        self.enc_dec_bar.setValue(0)

        self.send1_btn = QPushButton("send", self)
        self.send1_btn.setGeometry(770, 470, 130, 30)
        self.clear_content_btn = QPushButton("clear", self)
        self.clear_content_btn.setGeometry(920, 470, 130, 30)

        self.passw_label = QLabel("passw", self)
        self.passw_label.setGeometry(32, 510, 60, 30)
        self.passw_edit = QLineEdit(self)
        self.passw_edit.setGeometry(100, 510, 410, 30)

        self.clear_pwd_btn = QPushButton("clear", self)
        self.clear_pwd_btn.setGeometry(525, 510, 200, 30)

        self.clear_all_btn = QPushButton("clear all", self)
        self.clear_all_btn.setGeometry(770, 510, 280, 30)

        self.output_info = QTextBrowser(self)
        self.output_info.setGeometry(20, 550, 1030, 150)

        self.setGeometry(300, 300, 1080, 720)
        self.setWindowTitle('DES-secure Communication')    
        self.show()

    def set_onclick_listeners(self):
        self.connect_btn.clicked.connect(self.connect)
        self.send1_btn.clicked.connect(self.send_msg)
        self.file_btn.clicked.connect(self.open_file)
        self.clear_ses_btn.clicked.connect(self.clear_session)
        self.clear_content_btn.clicked.connect(self.clear_content)
        self.clear_pwd_btn.clicked.connect(self.clear_pwd)
        self.clear_all_btn.clicked.connect(self.clear_all)

    def handle_encoded_to_send(self, data: dict):
        content = data["data"]
        type = data["type"]
        if type == "file":
            base64_data = base64.decodebytes(content.encode())
            with open("./cache/cache_tosend.des", "wb") as f:
                f.write(base64_data)
            self.client.client_socket.send(json.dumps({"code": 2, "name": data["name"], "username": self.client.username}).encode("UTF-8"))
            t = SendFileThread(self.client, "./cache/cache_tosend.des", self)
            t.signal[str, int].connect(self.add_log)
            t.start()
        else:
            self.client.client_socket.send(json.dumps({"code": 1, "msg": content, "username": self.client.username}).encode("UTF-8"))

    def handle_remove_row(self, id):
        real_row_id = self.data_table.row_ids[id]
        if id != len(self.data_table.row_ids) - 1:
            for i in range(id+1, len(self.data_table.row_ids)):
                self.data_table.row_ids[i] -= 1
        else:
            self.data_table.row_ids[-1] -= 1
        self.data_table.table.removeRow(real_row_id)
        self.add_log("message in row {} removed".format(real_row_id+1), 0)
        # self.data_table.data.remove(self.data_table.data[id])

    def handle_enc_dec_bar(self, prog):
        self.enc_dec_bar.setValue(int(prog * 100))

    def add_log(self, msg: str, rp: int):
        self.output_info.append("{} {}".format(getTime(), msg))

    def update_table(self, data: dict):
        if data["code"] == 1:
            self.data_table.add_new_row({
                'sender': data["username"], 
                'data': data["msg"], 
                'status': 'received',
                'type': "text"})
            self.add_log("message from {} received".format(data["username"]), 0)
        elif data["code"] == 2:
            self.data_table.add_new_row({
                'sender': data["username"], 
                'data': data["name"], 
                'status': 'received',
                'type': "file"})
            self.add_log("file {} from {} received".format(data['name'], data["username"]), 0)

    def _start_server_thread(self, server: Server):
        server.start()

    def send_msg(self):
        content = self.content_edit.toPlainText()
        key = self.passw_edit.text()
        if self.path_edit.text() == "":
            self.enc_th = DesEncode(content, key, "text")
            self.enc_th._signal.connect(self.handle_encoded_to_send)
            self.enc_th._progress_signal.connect(self.handle_enc_dec_bar)
            self.enc_th.start()
        else:
            name = self.path_edit.text().split("/")[-1]
            self.enc_th = DesEncode(content, key, "file", name)
            self.enc_th._signal.connect(self.handle_encoded_to_send)
            self.enc_th._progress_signal.connect(self.handle_enc_dec_bar)
            self.enc_th.start()

    def open_file(self):
        fname = QFileDialog.getOpenFileName(self, 'open content file', '/')
        if fname[0]:
            self.path_edit.setText(fname[0])
            with open(fname[0], 'rb') as f_obj:
                base64_data = base64.b64encode(f_obj.read())
                self.content_edit.setText(base64_data.decode())

    def handle_data_retrieve(self, id):
        type = self.data_table.data[id]['type']
        data = self.data_table.data[id]['data']

        if type == "file":
            with open(os.path.join("./cache", data+".des"), 'rb') as f_obj:
                base64_data = base64.b64encode(f_obj.read())
                encoded = ''.join(base64_data.decode().split("\n"))
            encoded = bytes2binstr(base64.decodebytes(encoded.encode()))
            self.dec_th = DesDecode(encoded, self.passw_edit.text(), type, data)
            self.dec_th._signal.connect(self.decode_and_save)
            self.dec_th._progress_signal.connect(self.handle_enc_dec_bar)
            self.dec_th.start()
        else:
            encoded = bytes2binstr(base64.decodebytes(data.encode()))
            self.dec_th = DesDecode(encoded, self.passw_edit.text(), type, data)
            self.dec_th._signal.connect(self.decode_and_copy)
            self.dec_th._progress_signal.connect(self.handle_enc_dec_bar)
            self.dec_th.start()

    def decode_and_copy(self, data: dict):
        QApplication.clipboard().setText(data["data"].strip(" "))
        self.add_log("text message copied", 0)

    def decode_and_save(self, data: dict):
        name = data["name"]
        text = data["data"]
        
        base64_data = base64.b64decode(text.encode())
        fpath, type = QFileDialog.getSaveFileName(self, "save file", os.path.join("./", name))
        if fpath != '':
            with open(fpath, "wb") as f:
                f.write(base64_data)
            self.add_log("file message saved", 0)

    def clear_session(self):
        self.ses_edit.setText("")

    def clear_content(self):
        self.content_edit.setText("")
        self.path_edit.setText("")
        self.enc_dec_bar.setValue(0)

    def clear_pwd(self):
        self.passw_edit.setText("")

    def clear_all(self):
        self.clear_session()
        self.clear_content()
        self.clear_pwd()

    def stop_connection(self):
        if self.client is not None:
            self.client.close_all()
            self.client = None
        if self.server is not None:
            self.server.close_all()
            self.server = None

    def connect(self):
        if not self.connected:
            session_addr = self.ses_edit.text().split(":")
            if self.role_select.currentText() == "server":
                self.server = Server(session_addr[0], int(session_addr[1]))
                self.server.set_callback(self.add_log)
                self.server_thread = threading.Thread(target=self._start_server_thread, args=(self.server,))
                self.server_thread.start()
                time.sleep(1)
            self.client = Client(session_addr[0], int(session_addr[1]), session_addr[2])
            self.client.set_callbacks(self.add_log, self.update_table)
            self.client_thread = ConnectServerThread(self.client)
            self.client_thread.signal[dict].connect(self.update_table)
            self.client_thread.start()
            self.connect_btn.setText("disconnect")
            self.connected = True
        else:
            self.stop_connection()
            self.connect_btn.setText("connect")
            self.connected = False

    def closeEvent(self, event):
        result = QMessageBox.question(self, "DES-secure communication", "Do you want to exit?", QMessageBox.Yes | QMessageBox.No)
        if(result == QMessageBox.Yes):
            self.stop_connection()
            event.accept()
        else:
            event.ignore()



class ConnectServerThread(QThread):
    """
    CLASS: ConnectServerThread

    description: thread class for connecting the server
    """
    signal = pyqtSignal(dict)
 
    def __init__(self, client: Client, parent=None):
        super().__init__(parent)
        self.client = client
    
    def callback(self, msg: dict):
        self.signal.emit(msg)

    def run(self):
        self.client.connect_server()
        self.client.listen_server(self.callback)


class DesEncode(QThread):
    """
    DES encryption Thread
    """
    _signal = pyqtSignal(dict)
    _progress_signal = pyqtSignal(float)
 
    def __init__(self, data, key, type, name=None):
        super(DesEncode, self).__init__()
        
        self.data = data
        self.key = key
        self.type = type
        self.name = name
    
    def progress_callback(self, progress: float):
        if int(progress * 100) % 5 == 0:
            self._progress_signal.emit(progress)

    def run(self):
        encoded = des_encode(self.data, self.key, self.progress_callback)
        base64_encoded = base64.encodebytes(BytesIO(binstr2bytes(encoded)).read())
        if self.name is None:
            data = {"data": base64_encoded.decode(), "type": self.type}
        else:
            data = {"data": base64_encoded.decode(), "type": self.type, "name": self.name}
        self._signal.emit(data)


class DesDecode(QThread):
    """
    DES decryption Thread
    """
    _signal = pyqtSignal(dict)
    _progress_signal = pyqtSignal(float)
 
    def __init__(self, data, key, type, name=None):
        super(DesDecode, self).__init__()
        
        self.data = data
        self.key = key
        self.type = type
        self.name = name
    
    def progress_callback(self, progress: float):
        if int(progress * 100) % 5 == 0:
            self._progress_signal.emit(progress)

    def run(self):
        decoded = bin2str(
            des_decode(self.data, self.key, self.progress_callback), enc_n_bits=16).strip()
        if self.name is None:
            data = {"data": decoded, "type": self.type}
        else:
            data = {"data": decoded, "type": self.type, "name": self.name}
        self._signal.emit(data)


class SendFileThread(QThread):
    """
    CLASS: SendFileThread

    description: thread class for connecting the server
    """
    signal = pyqtSignal(str, int)
 
    def __init__(self, client: Client, path: str, parent=None):
        super().__init__(parent)

        self.client = client
        self.path = path
    
    def callback(self, msg: str):
        self.signal.emit(msg, 0)

    def run(self):
        self.client.client_socket.send_file(self.path)
        self.callback("file transmission finished")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())
