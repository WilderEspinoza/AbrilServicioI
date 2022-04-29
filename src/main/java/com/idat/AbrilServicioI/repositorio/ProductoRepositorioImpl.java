package com.idat.AbrilServicioI.repositorio;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Repository;

import com.idat.AbrilServicioI.modelo.Productos;

@Repository
public class ProductoRepositorioImpl implements ProductoRepositorio {
	
	public List<Productos> listar = new ArrayList<Productos>();

	
	@Override
	public void guardarProducto(Productos producto) {

		listar.add(producto);
	}

	@Override
	public void editarProducto(Productos producto) {
			
		listar.remove(obtenerProductoId(producto.getIdProducto()));
		listar.add(producto);
	}

	@Override
	public void eliminarProducto(Integer id) {
		
		listar.remove(obtenerProductoId(id));
	}

	@Override
	public List<Productos> listarProductos() {

		return listar;
	}

	@Override
	public Productos obtenerProductoId(Integer id) {
		
//		if(id != null) {
//			for (Productos productos : listar) {
//				
//				if(productos.getIdProducto() == id)
//					return productos;
//				else
//					return null;
//				
//			}
//		}else {
//			return null;
//		}

		
		return listar.stream().filter(producto ->producto.getIdProducto() == id).findFirst().orElse(null);
	}

}
