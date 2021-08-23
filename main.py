from PyQt5 import QtWidgets, uic, QtCore, QtGui
from PyQt5.QtWidgets import QMessageBox
import pyperclip
import keyring
import re
import hashlib
import pyotp,base64
import datetime
import qrcode
from pyzbar.pyzbar import decode
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import sys,os

if os.path.exists("Auther.db")==False:
	with open("Auther.db",'w') as file:
		file.close()
USERNAME=os.getenv('username')
if keyring.get_password("Auther",USERNAME)==None:
	PASS=get_random_bytes(32).hex()
	def encrypt_string(Pass):
		sha_signature = \
			hashlib.sha256(Pass.encode()).hexdigest()
		return sha_signature[0:32]
	PASS=encrypt_string(PASS)
	keyring.set_password("Auther", USERNAME, PASS)
cipher = AES.new(keyring.get_password("Auther",USERNAME).encode(), AES.MODE_CBC,keyring.get_password("Auther",USERNAME).encode()[:16])

class Ui(QtWidgets.QMainWindow):
	def __init__(self):
		super(Ui, self).__init__()
		uic.loadUi('.\\lib\Auther.ui', self)
		self.setWindowFlags(self.windowFlags() | QtCore.Qt.FramelessWindowHint )
		self.setAttribute(QtCore.Qt.WA_TranslucentBackground, True)
		self.show()
		self.topBar.mouseMoveEvent=self.moveWindow
		self.topBar.mousePressEvent=self.pressWindow
		self.topBar.mouseReleaseEvent=self.releasedWindow
		self.imageDropper.dragEnterEvent=self.dragEnterEvent
		self.imageDropper.dragMoveEvent=self.dragMoveEvent
		self.imageDropper.dropEvent=self.dropEvent
		self.imageDropper.mousePressEvent=self.labelPressEvent
		self.url=""
		self.exitButton.clicked.connect(lambda:self.exitMethod())
		self.minimizeButton.clicked.connect(lambda:self.showMinimized())
		self.restoreButton.clicked.connect(lambda:self.showMinimized())
		Text="""Auther is an open source 2FA Manager.\nAuther uses Military grade AES-256 to encrypt user data with a randomly generated key. Auther works does not require active internet connection as all the files are stored locally, Including Auth Codes.\n\nAuther Version: V1.7a\n\n\nAll the vector images are taken from https://icons8.com/"""
		self.infoButton.clicked.connect(lambda:self.MessageBox(QMessageBox.Information,Text,"Application Info",QMessageBox.Ok).exec())
		self.authTable.setRowCount(0)
		self.authTable.cellDoubleClicked.connect(lambda:self.copy_code())
		self.addButton.clicked.connect(lambda:self.add_url())
		self.cancelFAButton.clicked.connect(lambda:self.main_window())
		self.cancelExportButton.clicked.connect(lambda:self.main_window())
		self.verifyFAButton.clicked.connect(lambda:self.verify_link())
		self.verifyOTPButton.clicked.connect(lambda:self.verify_OTP())
		self.authTable.cellPressed.connect(lambda:self.editMethod())
		self.deleteButton.clicked.connect(lambda:self.delete_auth_code())
		self.exportButton.clicked.connect(lambda:self.export_auth_code())
		self.imageDropper.setAcceptDrops(True)
		self.progressBarValue(0)
		self.timer = QtCore.QTimer()
		self.timer.timeout.connect(self.progress)
		self.timer.start(30)
		self.populate_table()

	def labelPressEvent(self,event):
		try:
			if event.buttons() == QtCore.Qt.LeftButton:
				self.URLEdit.setText("")
				self.imageDropper.setPixmap(QtGui.QPixmap(".\\assets\images\DND.png"))
				filename=QtWidgets.QFileDialog.getOpenFileName()
				file_path=filename[0]
				self.set_image(file_path)
		except:
			self.URLEdit.setText("")
			self.imageDropper.setPixmap(QtGui.QPixmap(".\\assets\images\DND.png"))
		
	def exitMethod(self):
		self.showMinimized()
		app.exit()

	def moveWindow(self,event):
		try:
			if event.buttons() == QtCore.Qt.LeftButton:
				self.move(self.pos() + event.globalPos() - self.dragPos)
				self.dragPos = event.globalPos()
			event.accept()
		except:
			pass
	def pressWindow(self,event):
		try:
			self.dragPos = event.globalPos()
		except:
			pass
	def releasedWindow(self,event):
		pass

	def dragEnterEvent(self,event):
		if event.mimeData().hasImage:
			event.accept()
		else:
			event.ignore()
	def dragMoveEvent(self,event):
		if event.mimeData().hasImage:
			event.accept()
		else:
			event.ignore()
	def dropEvent(self,event):
		if event.mimeData().hasImage:
			event.setDropAction(QtCore.Qt.CopyAction)
			file_path = event.mimeData().urls()[0].toLocalFile()
			self.set_image(file_path)
			event.accept()
		else:
			event.ignore()
	def set_image(self,file_path):
		self.imageDropper.setPixmap(QtGui.QPixmap(file_path))
		self.url=decode(Image.open(file_path))
		for barcode in self.url:
			self.url=barcode.data.decode()
		self.URLEdit.setText(self.url)
		self.URLEdit.setReadOnly(True)

	def verify_OTP(self):
		OTP=self.authEdit.text()
		if pyotp.TOTP(self.parsed_url.secret).verify(OTP):
			self.MessageBox(QMessageBox.Information,"Authentication Code Validated!","Valid Code",QMessageBox.Ok).exec()
			KEY_GEN=self.url
			cipher = AES.new(keyring.get_password("Auther",USERNAME).encode(), AES.MODE_CBC,keyring.get_password("Auther",USERNAME).encode()[:16])
			KEY_GEN=pad(KEY_GEN.encode(),cipher.block_size)
			ENC_CODE=base64.b64encode(cipher.encrypt(base64.b64encode(KEY_GEN))).decode()
			with open('Auther.db','a') as file:
				file.write(str(ENC_CODE)+"\n")
			self.main_window() 
		else:
			self.MessageBox(QMessageBox.Warning,"Authentication Code Invalid","Invalid Code",QMessageBox.Ok).exec()

	def verify_link(self):
		reg=r"otpauth:\/\/totp\/.+secret=.+&issuer=.+"
		if self.url=="" or self.url.isspace():
			self.url=self.URLEdit.text()
		if (re.match(reg,self.url) or re.match(reg,self.URLEdit.text())) and (self.url==self.URLEdit.text()):
			self.verifyOTP.raise_()
			self.cancelFAButton.raise_()
			self.imageDropper.setPixmap(QtGui.QPixmap(".\\assets\images\DND.png"))
			self.URLEdit.setText("")		
			link=self.URLEdit.text()
			self.parsed_url = pyotp.parse_uri(self.url)
			self.totp = pyotp.TOTP(self.parsed_url.secret)
		else:
			self.MessageBox(QMessageBox.Warning,"The link entered is invalid!","Invalid Link",QMessageBox.Ok).exec()

	def main_window(self):
		self.editWidget.setEnabled(False)
		self.populate_table()
		self.url=""
		self.exportAuthText.setText("")
		self.exportAuthImg.setPixmap(QtGui.QPixmap(".\\assets\images\ExportBG.png"))
		self.authWidget.raise_()
		self.cancelFAButton.raise_()
		self.imageDropper.setPixmap(QtGui.QPixmap(".\\assets\images\DND.png"))
		self.URLEdit.setText("")
		self.authEdit.setText("")

	def add_url(self):
		self.dropURL.raise_()
		self.addAuthWidget.raise_()
		self.cancelFAButton.raise_()
		self.URLEdit.setReadOnly(False)

	def copy_code(self):
		SelectedCode=self.authTable.cellWidget(self.authTable.currentRow(),0).text()
		SelectedCode=SelectedCode.split("h2>")[1][0:-2]
		pyperclip.copy(SelectedCode)
		
	def progress(self):
		value=self.counter
		if value >= 100: value = 0.001
		if self.counter>=100:
			self.counter=0
			self.populate_table()
		self.progressBarValue(value)
		self.timerLabel.setText(str(30-int((value/100)*30)))
		self.counter+=0.1

	def progressBarValue(self,value):
		
		styleSheet = """
		QFrame {background-color: qconicalgradient(cx:0.5, cy:0.5, angle:90, stop:{STOP_1} rgba(0, 168, 255, 201), stop:{STOP_2} rgba(255, 255, 255, 0));
border-width: 0;
border-style: solid;
border-radius:45;
border-color: rgb(0,0,0);
}"""
		progress = (100 - value) / 100.0
		stop_1 = str(abs(progress - 0.001))
		stop_2 = str(abs(progress))
		newStylesheet = styleSheet.replace("{STOP_1}", stop_1).replace("{STOP_2}", stop_2)
		self.timerBar.setStyleSheet(newStylesheet)

	def populate_table(self):
		self.authTable.setRowCount(0)
		with open('Auther.db','r') as file:
			rows=file.read()
		rows=rows.split("\n")
		for row in rows:
			temp=""
			try:
				cipher = AES.new(keyring.get_password("Auther",USERNAME).encode(), AES.MODE_CBC,keyring.get_password("Auther",USERNAME).encode()[:16])
				temp=base64.b64decode(row.encode())
				temp=base64.b64decode(cipher.decrypt(temp))
				temp=unpad(temp,cipher.block_size).decode()
				self.parsed_url=pyotp.parse_uri(temp)
				CODE,SERVICE_NAME,CONSUMER=self.parsed_url.secret,self.parsed_url.issuer,self.parsed_url.name
				totp=pyotp.TOTP(CODE)
				CODE=totp.now()
				widgetText =  QtWidgets.QLabel(f"<h4>{SERVICE_NAME} ({CONSUMER})</h4><h2>{CODE}</h2>")
				widgetText.setStyleSheet('font: 10pt "Quicksand";\ncolor:rgb(189, 189, 189);\nbackground-color:transparent;')
				row=self.authTable.rowCount()
				self.authTable.insertRow(row)
				self.authTable.setCellWidget(row, 0, widgetText)
			except:
				pass
		time_remaining = 30 - datetime.datetime.now().timestamp() % 30
		self.counter=0
		self.counter=100-time_remaining/30*100
	
	def export_auth_code(self):
		self.editWidget.setEnabled(True)
		ACTION = self.MessageBox(QMessageBox.Warning,"You are about to export auth URL, Are you sure?","Auth Manager",QMessageBox.Yes | QMessageBox.No).exec()
		if ACTION==QMessageBox.Yes:
			ROW=self.authTable.currentRow()
			with open("Auther.db",'r') as file:
				rows=file.read()
				rows=rows.split("\n")
				row=rows[ROW]
				cipher = AES.new(keyring.get_password("Auther",USERNAME).encode(), AES.MODE_CBC,keyring.get_password("Auther",USERNAME).encode()[:16])
				temp=base64.b64decode(row.encode())
				temp=base64.b64decode(cipher.decrypt(temp))
				temp=unpad(temp,cipher.block_size).decode()
				img = qrcode.make(temp)
				self.change_to_export(img,temp)
	
	def change_to_export(self,img,URL):
		img.save(".\\assets\\temp.png")
		self.exportAuthImg.setPixmap(QtGui.QPixmap(".\\assets\\temp.png"))
		os.remove(".\\assets\\temp.png")
		self.exportAuthText.setText(URL)
		URL=""
		self.exportAuthWidget.raise_()

	def editMethod(self):
		if self.authTable.currentRow()!=None:
			self.editWidget.setEnabled(True)
			
	def delete_auth_code(self):
			self.editWidget.setEnabled(True)
			ACTION = self.MessageBox(QMessageBox.Warning,"Are you sure you want to delete?","Auth Manager",QMessageBox.Yes | QMessageBox.No).exec()
			if ACTION==QMessageBox.Yes:
				ROW=self.authTable.currentRow()
				with open("Auther.db",'r') as file:
					rows=file.read()
					rows=rows.split("\n")
					rows.pop(ROW)
				with open("Auther.db",'w') as file:
					file.writelines("%s\n" % l for l in rows if l!="")
				self.disable_edit_method(self.authTable.removeRow(self.authTable.currentRow()))
				self.editWidget.setEnabled(False)

	def disable_edit_method(self,event):
		self.editWidget.setEnabled(False)

	def MessageBox(self, Icon, Text, Title, Buttons):
		msgBox = QMessageBox()
		msgBox.setWindowIcon(QtGui.QIcon('.\\assets\images\Logo.png'))
		msgBox.setIcon(Icon)
		msgBox.setText(Text)
		msgBox.setWindowTitle(Title)
		msgBox.setStandardButtons(Buttons)
		return msgBox

if __name__=="__main__":
	app = QtWidgets.QApplication(sys.argv)
	window = Ui()
	app.exec_()
