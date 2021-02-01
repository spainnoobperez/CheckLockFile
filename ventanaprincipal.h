#ifndef VENTANAPRINCIPAL_H
#define VENTANAPRINCIPAL_H

#include <QMainWindow>
#include <QFileDialog>
#include <QMessageBox>

QT_BEGIN_NAMESPACE
namespace Ui { class VentanaPrincipal; }
QT_END_NAMESPACE

class VentanaPrincipal : public QMainWindow
{
    Q_OBJECT

public:
    VentanaPrincipal(QWidget *parent = nullptr);
    void Cambiar();
    void busqLock();
    ~VentanaPrincipal();

private:
    Ui::VentanaPrincipal *ui;
    QString filetoproc;
};
#endif // VENTANAPRINCIPAL_H
