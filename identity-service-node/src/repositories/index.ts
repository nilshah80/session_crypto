// Repository interfaces
export * from './interfaces';

// Repository implementations
export * from './implementations';

// Repository instances (singleton pattern)
import { SessionRepositoryImpl } from './implementations/session.repository.impl';
import { BaseRepositoryImpl } from './implementations/base.repository.impl';

// Create a concrete base repository for utility operations like health checks
class UtilityRepository extends BaseRepositoryImpl {
  protected mapRowToEntity(row: any): any {
    return row;
  }

  protected mapEntityToRow(entity: any): any {
    return entity;
  }
}

// Export singleton instances
export const sessionRepository = new SessionRepositoryImpl();
export const baseRepository = new UtilityRepository();
