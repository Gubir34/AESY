from setuptools import setup, find_packages

setup(
    name='AESY',  # Kütüphanenizin adı
    version='1.0.0',  # Kütüphanenizin versiyonu
    packages=find_packages(),  # Kütüphanenin bulunduğu paketleri otomatik olarak bulur
    install_requires=[  # Kütüphanenin bağımlılıkları (örneğin, Crypto, pycryptodome vb.)
        'pycryptodome',
    ],
    author='Can TEOMAN',  # Yazar bilgisi
    author_email='canteoman15@gmail.com',  # Yazar e-posta adresi
    description='A simple advanced encryption library for encrypting/decrypting data',
    long_description=open('README.md').read(),  # README dosyasının içeriği
    long_description_content_type='text/markdown',
    url='https://github.com/Gubir34/AESY',  # GitHub repo URL
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',  # Lisans bilgisi
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3 :: Only',
        'Intended Audience :: Developers',
    ],
)
